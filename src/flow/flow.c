#include "flow/flow.h"

#include <errno.h>
#include <stdlib.h>

struct flow {
    uint32_t local_ip;
    struct flow_table *table;

    flow_evict_cb on_evict;
    void *evict_user;
};

static int handoff_eviction(const struct flow_entry *entry, void *user) {
    const struct flow *flow = user;

    if (flow->on_evict == NULL) {
        errno = ENOSPC;

        return -1;
    }

    return flow->on_evict(entry, flow->evict_user);
}

struct flow *flow_create(uint32_t local_ip, size_t bucket_count, size_t capacity) {
    struct flow *flow = malloc(sizeof *flow);

    if (flow == NULL) {
        return NULL;
    }

    flow->table = flow_table_create(bucket_count, capacity);

    if (flow->table == NULL) {
        free(flow);

        return NULL;
    }

    flow->local_ip = local_ip;
    flow->on_evict = NULL;
    flow->evict_user = NULL;

    flow_table_set_eviction_handler(flow->table, handoff_eviction, flow);

    return flow;
}

void flow_destroy(struct flow *flow) {
    if (flow == NULL) {
        return;
    }

    flow_table_destroy(flow->table);
    free(flow);
}

int flow_observe(const struct flow *flow, const struct packet_view *packet, int64_t now) {
    if (packet->kind != PACKET_TCP && packet->kind != PACKET_UDP) {
        return 0;
    }

    const int outgoing = packet->ip.src == flow->local_ip;
    const int incoming = packet->ip.dst == flow->local_ip;

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

    const struct flow_key key = {
        .us_ip = flow->local_ip,
        .remote_ip = outgoing ? packet->ip.dst : packet->ip.src,
        .remote_port = outgoing ? destination_port : source_port,
        .protocol = packet->ip.protocol
    };

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
