#include "flow/flow_table.h"

#include <errno.h>
#include <stdlib.h>

struct flow_entry {
    struct flow_key key;
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

    if (table->count == table->capacity) {
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
