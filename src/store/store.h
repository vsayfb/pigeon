#ifndef PIGEON_STORE_H
#define PIGEON_STORE_H

#include "flow/flow_table.h"

#define STORE_ERROR_LEN 256
#define STORE_NAME_LEN 254

struct store;

/* A copied conversation snapshot. Empty remote_name represents SQL NULL.
 * On flush, delta contains increments; on lookup, it contains stored totals. */
struct store_row {
    struct flow_key key;
    struct flow_delta delta;
    char remote_name[STORE_NAME_LEN];
    int quic; /* QUIC observed within this UDP aggregate; not an identity field */
};

/*
 * Opens or creates path, or an isolated in-memory database for ":memory:".
 * Creates schema version 7 and migrates versions 1/2/3/4/5/6; rejects
 * unsupported versions. File databases use WAL and synchronous=FULL.
 * The caller owns the store and releases it with store_close(). error must
 * provide STORE_ERROR_LEN writable bytes. No database handle is borrowed.
 *
 * Returns the store on success, clearing error. Returns NULL and writes an
 * explanation to error on failure. Requires SQLite 3.24.0 or newer.
 */
struct store *store_open(const char *path, char error[STORE_ERROR_LEN]);

/* Finalizes statements and closes the database. Accepts NULL. */
void store_close(struct store *store);

/*
 * Adds count rows to cumulative totals in one transaction. Rows are borrowed
 * for the call and remain unchanged. NULL rows is valid only for count zero.
 * Counters must fit signed 64-bit integers, names must be NUL terminated,
 * and first_seen must not exceed last_seen. Existing names are preserved;
 * an unnamed row may acquire a name. Timestamps retain their minimum/maximum.
 * Replaying an already successful batch adds its counters again.
 *
 * Returns 0 on success. Returns -1 with store_error() set on failure; no
 * partial batch is committed. Pending in-memory deltas are never cleared.
 */
int store_flush(struct store *store, const struct store_row *rows, size_t count);

/*
 * Looks up key, copying cumulative totals and name into out on success.
 * No returned field borrows database memory.
 *
 * Returns 1 if found, 0 if absent, or -1 with store_error() set on failure.
 * Leaves out untouched when absent or on failure.
 */
int store_lookup(struct store *store, const struct flow_key *key, struct store_row *out);

/* Deletes one conversation, or all conversations and DNS history when key
 * is NULL. Atomic; returns 0 on success or -1 with store_error set. */
int store_delete(struct store *store, const struct flow_key *key);

/* Returns a borrowed explanation of the last error, valid until the next
 * store operation or close. Successful operations clear the explanation. */
const char *store_error(const struct store *store);

struct store_dns_row {
    struct ip_addr ip;
    char name[STORE_NAME_LEN];
    int64_t observed_at;
    int64_t expires_at;
};

/* Saves one mapping atomically. Equal timestamps allow replacement; older
 * observations cannot replace newer ones. The row is borrowed for the call.
 * Returns 1 if saved, 0 if older and ignored, or -1 with store_error() set
 * on failure. A failed save leaves the database unchanged. */
int store_dns_save(struct store *store, const struct store_dns_row *row);

/* Visits unexpired rows in observation-time order. Rows and user are borrowed
 * during the call; the callback must not operate on store. The callback
 * returns 0 on success, or -1 to stop loading. Returns 0 on success or -1
 * with store_error() set on query/callback failure. Earlier callback effects
 * are not rolled back. now is Unix seconds; expiry is exclusive. */
int store_dns_load(struct store *store, int64_t now,
                    int (*visit)(const struct store_dns_row *row, void *user), void *user);

#endif
