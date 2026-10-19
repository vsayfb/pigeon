#ifndef PIGEON_FLOW_TABLE_H
#define PIGEON_FLOW_TABLE_H

#include <stddef.h>

#include "flow/flow_key.h"

struct flow_table;
struct flow_entry;

/*
 * Allocates an empty table with bucket_count buckets. Entries use separate
 * chaining; bucket_count controls distribution, not the number of entries.
 * The caller owns the table and releases it with flow_table_destroy().
 *
 * Returns the table on success. Returns NULL with errno set to EINVAL for
 * zero buckets, or ENOMEM if allocation fails or the size would overflow.
 */
struct flow_table *flow_table_create(size_t bucket_count);

/* Frees all entries and the table. Accepts NULL. */
void flow_table_destroy(struct flow_table *table);

/*
 * Finds a key. Returns its table-owned entry, or NULL if absent.
 * The pointer remains valid until removal or table destruction.
 */
struct flow_entry *flow_table_find(const struct flow_table *table,
                                   const struct flow_key *key);

/*
 * Inserts a copy of key, or returns the existing entry for an equal key.
 * The table owns the entry; insertion never invalidates existing pointers.
 *
 * Returns the entry on success. Returns NULL with errno set to ENOMEM on
 * allocation failure, leaving the table unchanged.
 */
struct flow_entry *flow_table_insert(struct flow_table *table,
                                     const struct flow_key *key);

/* Frees the matching entry. Returns 1 if removed, or 0 if absent. */
int flow_table_remove(struct flow_table *table, const struct flow_key *key);

/* Returns the number of entries. */
size_t flow_table_count(const struct flow_table *table);

/* Returns the entry's borrowed, immutable key, valid for the entry's lifetime. */
const struct flow_key *flow_entry_key(const struct flow_entry *entry);

#endif
