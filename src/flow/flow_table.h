#ifndef PIGEON_FLOW_TABLE_H
#define PIGEON_FLOW_TABLE_H

#include <stddef.h>

#include "flow/flow_key.h"

#define FLOW_NAME_LEN 254

struct flow_table;
struct flow_entry;

/* Pending payload traffic and absolute observation times in Unix seconds. */
struct flow_delta {
    uint64_t packets_out;
    uint64_t packets_in;
    uint64_t bytes_out;
    uint64_t bytes_in;
    int64_t first_seen;
    int64_t last_seen;
};

/* Called before capacity eviction. The entry is borrowed for the call.
 * Returns 0 to allow eviction, or -1 with errno set to preserve the entry.
 * The callback must not modify the table or retain the entry pointer. */
typedef int (*flow_evict_cb)(const struct flow_entry *entry, void *user);

/*
 * Allocates an empty table with bucket_count buckets. Entries use separate
 * chaining; bucket_count controls distribution, not the number of entries.
 * capacity is the maximum number of entries and must be nonzero.
 * The caller owns the table and releases it with flow_table_destroy().
 *
 * Returns the table on success. Returns NULL with errno set to EINVAL for
 * zero buckets or capacity, or ENOMEM if allocation fails or the size would
 * overflow.
 */
struct flow_table *flow_table_create(size_t bucket_count, size_t capacity);

/* Frees all entries and the table. Accepts NULL. */
void flow_table_destroy(struct flow_table *table);

/*
 * Finds a key. Returns its table-owned entry, or NULL if absent.
 * The pointer remains valid until removal, eviction or table destruction.
 */
struct flow_entry *flow_table_find(const struct flow_table *table,
                                   const struct flow_key *key);

/*
 * Inserts a copy of key, or returns the existing entry for an equal key.
 * New entries become the newest; duplicate insertion and lookup preserve
 * list order. At capacity, a new key evicts and frees the oldest entry.
 * The table owns all entries. Pointers to surviving entries remain valid.
 *
 * Returns the entry on success. Returns NULL with errno set to ENOMEM on
 * allocation failure, leaving the table unchanged. Allocation precedes
 * eviction, so allocation failure never removes an entry. An eviction
 * callback failure also returns NULL, preserving the table and its errno.
 */
struct flow_entry *flow_table_insert(struct flow_table *table,
                                     const struct flow_key *key);

/*
 * Moves an existing entry to the newest end. Returns its borrowed pointer,
 * or NULL if absent, leaving the table unchanged. Does not allocate or evict.
 */
struct flow_entry *flow_table_touch(struct flow_table *table,
                                    const struct flow_key *key);

/* Frees the matching entry. Returns 1 if removed, or 0 if absent. */
int flow_table_remove(struct flow_table *table, const struct flow_key *key);

/* Returns the number of entries. */
size_t flow_table_count(const struct flow_table *table);

/* Returns the entry's borrowed, immutable key, valid for the entry's lifetime. */
const struct flow_key *flow_entry_key(const struct flow_entry *entry);

/* Returns the maximum number of entries. */
size_t flow_table_capacity(const struct flow_table *table);

/* Returns the newest or oldest borrowed entry, or NULL for an empty table.
 * Entry pointers remain valid until removal, eviction or table destruction. */
const struct flow_entry *flow_table_newest(const struct flow_table *table);
const struct flow_entry *flow_table_oldest(const struct flow_table *table);

/* Returns the neighboring borrowed entry, or NULL at that end of the list. */
const struct flow_entry *flow_entry_older(const struct flow_entry *entry);
const struct flow_entry *flow_entry_newer(const struct flow_entry *entry);

/* Sets an optional capacity-eviction callback and its borrowed context.
 * NULL allows eviction without notification. Removal and destruction do
 * not invoke this callback. */
void flow_table_set_eviction_handler(struct flow_table *table, flow_evict_cb cb, void *user);

/* Returns borrowed counters, valid for the entry's lifetime. */
const struct flow_delta *flow_entry_delta(const struct flow_entry *entry);

/* Copies delta into the entry. Does not change recency. */
void flow_entry_set_delta(struct flow_entry *entry, const struct flow_delta *delta);

/* Returns the borrowed first assigned name, or an empty string if unnamed. */
const char *flow_entry_name(const struct flow_entry *entry);

/* Copies name only into an unnamed entry and marks its name pending storage.
 * name must be NUL terminated and shorter than FLOW_NAME_LEN bytes. */
void flow_entry_set_name(struct flow_entry *entry, const char *name);

/* Reports/clears a name awaiting successful persistence. */
int flow_entry_name_pending(const struct flow_entry *entry);
void flow_entry_clear_name_pending(struct flow_entry *entry);

#endif
