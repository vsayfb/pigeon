#include "flow/flow_table.h"

#include <errno.h>
#include <stdlib.h>

struct flow_entry {
    struct flow_key key;
    struct flow_entry *next;
};

struct flow_table {
    struct flow_entry **buckets;
    size_t bucket_count;
    size_t count;
};

struct flow_table *flow_table_create(size_t bucket_count) {
    if (bucket_count == 0) {
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

    const size_t bucket = flow_key_hash(key) % table->bucket_count;

    entry->key = *key;
    entry->next = table->buckets[bucket];
    table->buckets[bucket] = entry;
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
