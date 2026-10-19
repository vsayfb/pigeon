#include "flow/flow.h"
#include "store/store.h"
#include "dns/dns_cache.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct flow {
    struct ip_addr *local_addresses;
    size_t local_count;
    struct flow_table *table;

    flow_evict_cb on_evict;
    void *evict_user;

    struct store *store;
    struct dns_cache *dns;
    int tick_started;
    int64_t last_tick;
    int64_t name_time;
    int clock_set;
    void (*resolve_application)(const struct flow_key *, uint16_t, char [FLOW_APP_LEN], void *);
    void *application_user;
};

static const char *lookup_name(const struct flow *flow, const struct flow_entry *entry) {
    if (flow_entry_name(entry)[0] != '\0') {
        return flow_entry_name(entry);
    }

    if (flow->dns == NULL) {
        return NULL;
    }

    const int64_t now = flow->clock_set ? flow->name_time
                                       : flow_entry_delta(entry)->last_seen;

    return dns_cache_lookup(flow->dns, flow_entry_key(entry)->remote_ip, now);
}

static int needs_flush(const struct flow *flow, const struct flow_entry *entry) {
    const struct flow_delta *delta = flow_entry_delta(entry);

    return delta->packets_out != 0 || delta->packets_in != 0 ||
           flow_entry_name_pending(entry) ||
           (flow_entry_name(entry)[0] == '\0' && lookup_name(flow, entry) != NULL);
}

static void snapshot_row(const struct flow *flow, const struct flow_entry *entry,
                          struct store_row *row) {
    row->key = *flow_entry_key(entry);
    row->delta = *flow_entry_delta(entry);

    const char *name = lookup_name(flow, entry);

    if (name != NULL) {
        memcpy(row->remote_name, name, strlen(name) + 1);
    }
}

static int handoff_eviction(const struct flow_entry *entry, void *user) {
    const struct flow *flow = user;

    if (flow->store != NULL) {
        if (!needs_flush(flow, entry)) {
            return 0;
        }

        struct store_row row = { 0 };

        snapshot_row(flow, entry, &row);

        if (store_flush(flow->store, &row, 1) == -1) {
            errno = EIO;

            return -1;
        }

        return 0;
    }

    if (flow->on_evict == NULL) {
        errno = ENOSPC;

        return -1;
    }

    return flow->on_evict(entry, flow->evict_user);
}

struct flow *flow_create_addresses(const struct ip_addr *addresses, size_t count,
                                    size_t bucket_count, size_t capacity) {
    if (addresses == NULL || count == 0 || count > SIZE_MAX / sizeof *addresses) {
        errno = EINVAL;

        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        if (ip_addr_size(&addresses[i]) == 0) {
            errno = EINVAL;

            return NULL;
        }
    }

    struct flow *flow = malloc(sizeof *flow);

    if (flow == NULL) {
        return NULL;
    }

    flow->local_addresses = malloc(count * sizeof *addresses);

    if (flow->local_addresses == NULL) {
        free(flow);

        return NULL;
    }

    memcpy(flow->local_addresses, addresses, count * sizeof *addresses);
    flow->local_count = count;
    flow->table = flow_table_create(bucket_count, capacity);

    if (flow->table == NULL) {
        free(flow->local_addresses);
        free(flow);

        return NULL;
    }

    flow->on_evict = NULL;
    flow->evict_user = NULL;
    flow->store = NULL;
    flow->dns = NULL;
    flow->tick_started = 0;
    flow->last_tick = 0;
    flow->name_time = 0;
    flow->clock_set = 0;
    flow->resolve_application = NULL;
    flow->application_user = NULL;

    flow_table_set_eviction_handler(flow->table, handoff_eviction, flow);

    return flow;
}

void flow_destroy(struct flow *flow) {
    if (flow == NULL) {
        return;
    }

    flow_table_destroy(flow->table);
    free(flow->local_addresses);
    free(flow);
}

int flow_observe(struct flow *flow, const struct packet_view *packet, int64_t now) {
    if (packet->kind != PACKET_TCP && packet->kind != PACKET_UDP) {
        return 0;
    }

    const struct ip_addr source = packet_source(packet);
    const struct ip_addr destination = packet_destination(packet);
    int outgoing = 0;
    int incoming = 0;

    for (size_t i = 0; i < flow->local_count; i++) {
        outgoing |= ip_addr_equal(&source, &flow->local_addresses[i]);
        incoming |= ip_addr_equal(&destination, &flow->local_addresses[i]);
    }

    if (outgoing == incoming) {
        return 0;
    }

    uint16_t source_port;
    uint16_t destination_port;

    if (packet->kind == PACKET_TCP) {
        source_port = packet->transport.tcp.src_port;
        destination_port = packet->transport.tcp.dst_port;
    } else {
        source_port = packet->transport.udp.src_port;
        destination_port = packet->transport.udp.dst_port;
    }

    struct flow_key key = {
        .us_ip = outgoing ? source : destination,
        .remote_ip = outgoing ? destination : source,
        .remote_port = outgoing ? destination_port : source_port,
        .protocol = packet_protocol(packet)
    };

    if (flow->resolve_application != NULL) {
        flow->resolve_application(&key, outgoing ? source_port : destination_port,
                                  key.application, flow->application_user);
        key.application[FLOW_APP_LEN - 1] = '\0';
    }

    flow->name_time = now;
    flow->clock_set = 1;

    struct flow_entry *entry = flow_table_find(flow->table, &key);
    const int is_new = entry == NULL;

    if (is_new) {
        entry = flow_table_insert(flow->table, &key);

        if (entry == NULL) {
            return -1;
        }
    }

    struct flow_delta delta = *flow_entry_delta(entry);

    const size_t payload = packet->kind == PACKET_TCP
                           ? packet->transport.tcp.payload_wire_len
                           : packet->transport.udp.payload_wire_len;

    if (outgoing) {
        delta.packets_out++;
        delta.bytes_out += payload;
    } else {
        delta.packets_in++;
        delta.bytes_in += payload;
    }

    if (is_new) {
        delta.first_seen = now;
        delta.last_seen = now;
    } else {
        if (now < delta.first_seen) {
            delta.first_seen = now;
        }

        if (now > delta.last_seen) {
            delta.last_seen = now;
        }
    }

    flow_entry_set_delta(entry, &delta);

    if (flow->dns != NULL && flow_entry_name(entry)[0] == '\0') {
        const char *name = dns_cache_lookup(flow->dns, key.remote_ip, now);

        if (name != NULL) {
            flow_entry_set_name(entry, name);
        }
    }

    flow_table_touch(flow->table, &key);

    return 1;
}

size_t flow_count(const struct flow *flow) {
    return flow_table_count(flow->table);
}

const struct flow_entry *flow_find(const struct flow *flow, const struct flow_key *key) {
    return flow_table_find(flow->table, key);
}

void flow_set_eviction_handler(struct flow *flow, flow_evict_cb cb, void *user) {
    flow->on_evict = cb;
    flow->evict_user = user;
}

void flow_visit(const struct flow *flow,
                void (*visit)(const struct flow_entry *entry, void *user), void *user) {
    for (const struct flow_entry *entry = flow_table_newest(flow->table);
         entry != NULL; entry = flow_entry_older(entry)) {
        visit(entry, user);
    }
}

void flow_set_store(struct flow *flow, struct store *store) {
    flow->store = store;
}

int flow_flush(struct flow *flow) {
    if (flow->store == NULL) {
        errno = ENOSYS;

        return -1;
    }

    size_t count = 0;

    for (const struct flow_entry *entry = flow_table_newest(flow->table);
         entry != NULL; entry = flow_entry_older(entry)) {
        if (needs_flush(flow, entry)) {
            count++;
        }
    }

    if (count == 0) {
        return 0;
    }

    if (count > SIZE_MAX / sizeof(struct store_row)) {
        errno = ENOMEM;

        return -1;
    }

    struct store_row *rows = calloc(count, sizeof *rows);

    if (rows == NULL) {
        return -1;
    }

    size_t index = 0;

    for (const struct flow_entry *entry = flow_table_newest(flow->table);
         entry != NULL; entry = flow_entry_older(entry)) {
        if (needs_flush(flow, entry)) {
            snapshot_row(flow, entry, &rows[index]);
            index++;
        }
    }

    if (store_flush(flow->store, rows, count) == -1) {
        free(rows);
        errno = EIO;

        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        struct flow_entry *entry = flow_table_find(flow->table, &rows[i].key);
        struct flow_delta cleared = rows[i].delta;

        cleared.packets_out = 0;
        cleared.packets_in = 0;
        cleared.bytes_out = 0;
        cleared.bytes_in = 0;

        flow_entry_set_delta(entry, &cleared);
        flow_entry_set_name(entry, rows[i].remote_name);
        flow_entry_clear_name_pending(entry);
    }

    free(rows);

    return 0;
}

int flow_tick(struct flow *flow, int64_t now) {
    flow->name_time = now;
    flow->clock_set = 1;

    if (flow->tick_started && now <= flow->last_tick) {
        return 0;
    }

    flow->tick_started = 1;
    flow->last_tick = now;

    if (flow_flush(flow) == -1) {
        return -1;
    }

    const struct flow_entry *entry = flow_table_oldest(flow->table);

    while (entry != NULL) {
        const struct flow_entry *next = flow_entry_newer(entry);
        const struct flow_delta *delta = flow_entry_delta(entry);
        const struct flow_key *key = flow_entry_key(entry);
        const uint64_t idle = key->protocol == IP_PROTO_UDP ? 30 : 120;

        if (now >= delta->last_seen &&
            (uint64_t)now - (uint64_t)delta->last_seen >= idle) {
            flow_table_remove(flow->table, key);
        }

        entry = next;
    }

    return 0;
}

void flow_set_dns_cache(struct flow *flow, struct dns_cache *cache) {
    flow->dns = cache;
}

struct flow *flow_create(uint32_t local_ip, size_t bucket_count, size_t capacity) {
    const struct ip_addr address = ip_addr_v4(local_ip);

    return flow_create_addresses(&address, 1, bucket_count, capacity);
}

void flow_set_application_resolver(struct flow *flow,
    void (*resolve)(const struct flow_key *, uint16_t, char [FLOW_APP_LEN], void *), void *user) {
    flow->resolve_application = resolve;
    flow->application_user = user;
}
