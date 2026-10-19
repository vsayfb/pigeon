#include "flow/flow_table.h"
#include "proto/quic.h"
#include "proto/transport.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct flow_entry {
    struct flow_key key;
    struct flow_delta delta;
    char name[FLOW_NAME_LEN];
    int name_pending;
    int quic;
    struct quic_probe quic_probe;
    struct flow_entry *next;

    struct flow_entry *newer;
    struct flow_entry *older;
};

struct flow_table {
    struct flow_entry **buckets;
    size_t bucket_count;
    size_t count;
    size_t capacity;

    struct flow_entry *newest;
    struct flow_entry *oldest;

    flow_evict_cb on_evict;
    void *evict_user;
};

static void unlink_recency(struct flow_table *table, struct flow_entry *entry) {
    if (entry->newer != NULL) {
        entry->newer->older = entry->older;
    } else {
        table->newest = entry->older;
    }

    if (entry->older != NULL) {
        entry->older->newer = entry->newer;
    } else {
        table->oldest = entry->newer;
    }
}

static void prepend_recency(struct flow_table *table, struct flow_entry *entry) {
    entry->newer = NULL;
    entry->older = table->newest;

    if (table->newest != NULL) {
        table->newest->newer = entry;
    } else {
        table->oldest = entry;
    }

    table->newest = entry;
}

struct flow_table *flow_table_create(size_t bucket_count, size_t capacity) {
    if (bucket_count == 0 || capacity == 0) {
        errno = EINVAL;

        return NULL;
    }

    if (bucket_count > SIZE_MAX / sizeof(struct flow_entry *)) {
        errno = ENOMEM;

        return NULL;
    }

    struct flow_table *table = malloc(sizeof *table);

    if (table == NULL) {
        return NULL;
    }

    table->buckets = calloc(bucket_count, sizeof *table->buckets);

    if (table->buckets == NULL) {
        free(table);

        return NULL;
    }

    table->bucket_count = bucket_count;
    table->count = 0;
    table->capacity = capacity;

    table->newest = NULL;
    table->oldest = NULL;

    table->on_evict = NULL;
    table->evict_user = NULL;

    return table;
}

void flow_table_destroy(struct flow_table *table) {
    if (table == NULL) {
        return;
    }

    for (size_t i = 0; i < table->bucket_count; i++) {
        struct flow_entry *entry = table->buckets[i];

        while (entry != NULL) {
            struct flow_entry *next = entry->next;

            free(entry);
            entry = next;
        }
    }

    free(table->buckets);
    free(table);
}

struct flow_entry *flow_table_find(const struct flow_table *table,
                                   const struct flow_key *key) {
    const size_t bucket = flow_key_hash(key) % table->bucket_count;

    for (struct flow_entry *entry = table->buckets[bucket];
         entry != NULL; entry = entry->next) {
        if (flow_key_equal(&entry->key, key)) {
            return entry;
        }
    }

    return NULL;
}

struct flow_entry *flow_table_insert(struct flow_table *table,
                                     const struct flow_key *key) {
    struct flow_entry *entry = flow_table_find(table, key);

    if (entry != NULL) {
        return entry;
    }

    entry = malloc(sizeof *entry);

    if (entry == NULL) {
        return NULL;
    }

    entry->key = *key;
    entry->delta = (struct flow_delta){ 0 };
    entry->name[0] = '\0';
    entry->name_pending = 0;
    entry->quic = 0;
    entry->quic_probe = (struct quic_probe){ 0 };

    if (table->count == table->capacity) {
        if (table->on_evict != NULL &&
            table->on_evict(table->oldest, table->evict_user) == -1) {
            const int saved_errno = errno;

            free(entry);
            errno = saved_errno;

            return NULL;
        }

        flow_table_remove(table, &table->oldest->key);
    }

    const size_t bucket = flow_key_hash(&entry->key) % table->bucket_count;

    entry->next = table->buckets[bucket];
    table->buckets[bucket] = entry;

    prepend_recency(table, entry);
    table->count++;

    return entry;
}

int flow_table_remove(struct flow_table *table, const struct flow_key *key) {
    const size_t bucket = flow_key_hash(key) % table->bucket_count;

    struct flow_entry **link = &table->buckets[bucket];

    while (*link != NULL) {
        struct flow_entry *entry = *link;

        if (flow_key_equal(&entry->key, key)) {
            *link = entry->next;

            unlink_recency(table, entry);

            free(entry);
            table->count--;

            return 1;
        }

        link = &entry->next;
    }

    return 0;
}

size_t flow_table_count(const struct flow_table *table) {
    return table->count;
}

const struct flow_key *flow_entry_key(const struct flow_entry *entry) {
    return &entry->key;
}

size_t flow_table_capacity(const struct flow_table *table) {
    return table->capacity;
}

const struct flow_entry *flow_table_newest(const struct flow_table *table) {
    return table->newest;
}

const struct flow_entry *flow_table_oldest(const struct flow_table *table) {
    return table->oldest;
}

const struct flow_entry *flow_entry_older(const struct flow_entry *entry) {
    return entry->older;
}

const struct flow_entry *flow_entry_newer(const struct flow_entry *entry) {
    return entry->newer;
}

struct flow_entry *flow_table_touch(struct flow_table *table,
                                    const struct flow_key *key) {
    struct flow_entry *entry = flow_table_find(table, key);

    if (entry != NULL && entry != table->newest) {
        unlink_recency(table, entry);
        prepend_recency(table, entry);
    }

    return entry;
}

void flow_table_set_eviction_handler(struct flow_table *table, flow_evict_cb cb, void *user) {
    table->on_evict = cb;
    table->evict_user = user;
}

const struct flow_delta *flow_entry_delta(const struct flow_entry *entry) {
    return &entry->delta;
}

void flow_entry_set_delta(struct flow_entry *entry, const struct flow_delta *delta) {
    entry->delta = *delta;
}

const char *flow_entry_name(const struct flow_entry *entry) {
    return entry->name;
}

void flow_entry_set_name(struct flow_entry *entry, const char *name) {
    if (entry->name[0] == '\0' && name[0] != '\0') {
        memcpy(entry->name, name, strlen(name) + 1);
        entry->name_pending = 1;
    }
}

int flow_entry_name_pending(const struct flow_entry *entry) {
    return entry->name_pending;
}

void flow_entry_clear_name_pending(struct flow_entry *entry) {
    entry->name_pending = 0;
}

int flow_entry_quic(const struct flow_entry *entry) {
    return entry->quic;
}

void flow_entry_observe_quic(struct flow_entry *entry, const struct udp_view *udp,
                              uint16_t local_port, int outgoing, int64_t now) {
    if (!entry->quic && quic_observe(&entry->quic_probe, udp->payload, udp->payload_len,
                                    udp->payload_wire_len, local_port, outgoing, now)) {
        entry->quic = 1;
    }
}
