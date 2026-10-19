#include "store/store.h"
#include "store/schema.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct store {
    sqlite3 *db;
    sqlite3_stmt *upsert;
    sqlite3_stmt *lookup;
    sqlite3_stmt *dns_save;
    sqlite3_stmt *dns_load;

    char error[STORE_ERROR_LEN];
    int unusable;
};

static int fail(struct store *store, const char *operation) {
    snprintf(store->error, sizeof store->error, "%s: %s",
             operation, sqlite3_errmsg(store->db));

    return -1;
}

static int execute(struct store *store, const char *sql) {
    if (sqlite3_exec(store->db, sql, NULL, NULL, NULL) != SQLITE_OK) {
        return fail(store, "SQL execution");
    }

    return 0;
}

static void rollback(struct store *store) {
    if (sqlite3_exec(store->db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK) {
        store->unusable = 1;
    }
}

static int scalar(struct store *store, const char *sql, int *value) {
    sqlite3_stmt *statement = NULL;

    if (sqlite3_prepare_v2(store->db, sql, -1, &statement, NULL) != SQLITE_OK) {
        return fail(store, "prepare scalar");
    }

    int rc = -1;

    if (sqlite3_step(statement) == SQLITE_ROW) {
        *value = sqlite3_column_int(statement, 0);
        rc = 0;
    } else {
        fail(store, "read scalar");
    }

    sqlite3_finalize(statement);

    return rc;
}

static void migrate_ipv4(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;

    const sqlite3_int64 value = sqlite3_value_int64(values[0]);

    if (sqlite3_value_type(values[0]) != SQLITE_INTEGER || value < 0 || value > UINT32_MAX) {
        sqlite3_result_error(context, "invalid IPv4 value in migration", -1);

        return;
    }

    const struct ip_addr address = ip_addr_v4((uint32_t)value);

    sqlite3_result_blob(context, address.bytes, 4, SQLITE_TRANSIENT);
}

static int initialize_schema(struct store *store) {
    if (execute(store, "BEGIN IMMEDIATE") == -1) {
        return -1;
    }

    int version;

    if (scalar(store, "PRAGMA user_version", &version) == -1) {
        goto error;
    }

    if (version == 0) {
        int objects;

        if (scalar(store, "SELECT count(*) FROM sqlite_master "
                   "WHERE name NOT LIKE 'sqlite_%'", &objects) == -1) {
            goto error;
        }

        if (objects != 0) {
            snprintf(store->error, sizeof store->error,
                     "unversioned database is not empty");
            goto error;
        }

        if (execute(store, STORE_SCHEMA_SQL) == -1) {
            goto error;
        }
    } else if (version == 1 || version == 2) {
        if (version == 1 && execute(store, STORE_DNS_V2_SQL) == -1) {
            goto error;
        }

        if (sqlite3_create_function_v2(store->db, "ipv4_blob", 1, SQLITE_UTF8,
                                       NULL, migrate_ipv4, NULL, NULL, NULL) != SQLITE_OK) {
            fail(store, "register IPv4 migration");
            goto error;
        }

        if (execute(store, STORE_MIGRATE_V2_SQL) == -1) {
            goto error;
        }
    } else if (version != 3 && version != SCHEMA_VERSION) {
        snprintf(store->error, sizeof store->error,
                 "unsupported schema version %d (expected %d)", version, SCHEMA_VERSION);
        goto error;
    }

    if (version >= 1 && version <= 3 && execute(store, STORE_MIGRATE_V3_SQL) == -1) {
        goto error;
    }

    if (execute(store, "COMMIT") == -1) {
        goto error;
    }

    return 0;

error:
    rollback(store);

    return -1;
}

static int enable_wal(struct store *store, const char *path) {
    sqlite3_stmt *statement = NULL;

    if (sqlite3_prepare_v2(store->db, "PRAGMA journal_mode=WAL", -1,
                           &statement, NULL) != SQLITE_OK) {
        return fail(store, "prepare WAL");
    }

    int rc = -1;

    if (sqlite3_step(statement) == SQLITE_ROW) {
        const char *mode = (const char *)sqlite3_column_text(statement, 0);
        const char *expected = strcmp(path, ":memory:") == 0 ? "memory" : "wal";

        if (mode != NULL && strcmp(mode, expected) == 0) {
            rc = 0;
        } else {
            snprintf(store->error, sizeof store->error, "WAL mode unavailable");
        }
    } else {
        fail(store, "enable WAL");
    }

    sqlite3_finalize(statement);

    return rc;
}

struct store *store_open(const char *path, char error[STORE_ERROR_LEN]) {
    struct store *store = calloc(1, sizeof *store);

    if (store == NULL) {
        snprintf(error, STORE_ERROR_LEN, "store allocation failed");

        return NULL;
    }

    if (sqlite3_open_v2(path, &store->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        NULL) != SQLITE_OK) {
        fail(store, "open database");
        goto error;
    }

    if (sqlite3_busy_timeout(store->db, 1000) != SQLITE_OK) {
        fail(store, "set busy timeout");
        goto error;
    }

    if (initialize_schema(store) == -1 || enable_wal(store, path) == -1 ||
        execute(store, "PRAGMA synchronous=FULL") == -1) {
        goto error;
    }

    if (sqlite3_prepare_v2(store->db, STORE_UPSERT_SQL, -1,
                           &store->upsert, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, STORE_LOOKUP_SQL, -1,
                           &store->lookup, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, STORE_DNS_UPSERT_SQL, -1,
                           &store->dns_save, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(store->db, STORE_DNS_LOAD_SQL, -1,
                           &store->dns_load, NULL) != SQLITE_OK) {
        fail(store, "prepare conversation statements");
        goto error;
    }

    error[0] = '\0';

    return store;

error:
    snprintf(error, STORE_ERROR_LEN, "%s", store->error);
    store_close(store);

    return NULL;
}

void store_close(struct store *store) {
    if (store == NULL) {
        return;
    }

    sqlite3_finalize(store->upsert);
    sqlite3_finalize(store->lookup);
    sqlite3_finalize(store->dns_save);
    sqlite3_finalize(store->dns_load);
    sqlite3_close(store->db);
    free(store);
}

static int bind_address(sqlite3_stmt *statement, int index, const struct ip_addr *address) {
    const size_t size = ip_addr_size(address);

    if (size == 0) {
        return SQLITE_MISMATCH;
    }

    return sqlite3_bind_blob(statement, index, address->bytes, (int)size, SQLITE_TRANSIENT);
}

static int read_address(sqlite3_stmt *statement, int column, struct ip_addr *address) {
    const int size = sqlite3_column_bytes(statement, column);
    const void *bytes = sqlite3_column_blob(statement, column);

    if (bytes == NULL || (size != 4 && size != 16)) {
        return -1;
    }

    address->family = size == 4 ? 4 : 6;
    memcpy(address->bytes, bytes, (size_t)size);

    return 0;
}

static int bind_key(sqlite3_stmt *statement, const struct flow_key *key) {
    if (memchr(key->application, '\0', sizeof key->application) == NULL) {
        return SQLITE_MISMATCH;
    }

    int rc = bind_address(statement, 1, &key->us_ip);

    if (rc == SQLITE_OK) {
        rc = bind_address(statement, 2, &key->remote_ip);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(statement, 3, key->remote_port);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(statement, 4, key->protocol);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(statement, 12, key->application, -1, SQLITE_TRANSIENT);
    }

    return rc;
}

static int write_row(struct store *store, const struct store_row *row) {
    const uint64_t counters[] = {
        row->delta.packets_out, row->delta.packets_in,
        row->delta.bytes_out, row->delta.bytes_in
    };

    if (memchr(row->remote_name, '\0', sizeof row->remote_name) == NULL) {
        snprintf(store->error, sizeof store->error, "remote name is not NUL terminated");

        return -1;
    }

    int rc = bind_key(store->upsert, &row->key);

    for (int i = 0; i < 4 && rc == SQLITE_OK; i++) {
        if (counters[i] > INT64_MAX) {
            snprintf(store->error, sizeof store->error, "counter exceeds signed 64-bit range");

            return -1;
        }

        rc = sqlite3_bind_int64(store->upsert, i + 5, (sqlite3_int64)counters[i]);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int64(store->upsert, 9, row->delta.first_seen);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int64(store->upsert, 10, row->delta.last_seen);
    }

    if (rc == SQLITE_OK) {
        rc = row->remote_name[0] == '\0' ? sqlite3_bind_null(store->upsert, 11)
             : sqlite3_bind_text(store->upsert, 11, row->remote_name, -1, SQLITE_TRANSIENT);
    }

    if (rc != SQLITE_OK || sqlite3_step(store->upsert) != SQLITE_DONE) {
        return fail(store, "upsert conversation");
    }

    return 0;
}

int store_flush(struct store *store, const struct store_row *rows, size_t count) {
    store->error[0] = '\0';

    if (store->unusable) {
        snprintf(store->error, sizeof store->error, "database requires reopening after rollback failure");

        return -1;
    }

    if (count == 0) {
        return 0;
    }

    if (rows == NULL) {
        snprintf(store->error, sizeof store->error, "rows is NULL for a nonempty batch");

        return -1;
    }

    if (execute(store, "BEGIN IMMEDIATE") == -1) {
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        const int rc = write_row(store, &rows[i]);

        sqlite3_reset(store->upsert);
        sqlite3_clear_bindings(store->upsert);

        if (rc == -1) {
            rollback(store);

            return -1;
        }
    }

    if (execute(store, "COMMIT") == -1) {
        rollback(store);

        return -1;
    }

    return 0;
}

int store_lookup(struct store *store, const struct flow_key *key, struct store_row *out) {
    store->error[0] = '\0';

    if (bind_key(store->lookup, key) != SQLITE_OK) {
        fail(store, "bind lookup");
        sqlite3_reset(store->lookup);
        sqlite3_clear_bindings(store->lookup);

        return -1;
    }

    const int rc = sqlite3_step(store->lookup);
    int result = 0;

    if (rc == SQLITE_ROW) {
        struct store_row row = { .key = *key };

        row.delta.packets_out = (uint64_t)sqlite3_column_int64(store->lookup, 0);
        row.delta.packets_in = (uint64_t)sqlite3_column_int64(store->lookup, 1);
        row.delta.bytes_out = (uint64_t)sqlite3_column_int64(store->lookup, 2);
        row.delta.bytes_in = (uint64_t)sqlite3_column_int64(store->lookup, 3);
        row.delta.first_seen = sqlite3_column_int64(store->lookup, 4);
        row.delta.last_seen = sqlite3_column_int64(store->lookup, 5);

        if (sqlite3_column_type(store->lookup, 6) != SQLITE_NULL) {
            const char *name = (const char *)sqlite3_column_text(store->lookup, 6);

            if (name == NULL) {
                fail(store, "read remote name");
                result = -1;
            } else {
                snprintf(row.remote_name, sizeof row.remote_name, "%s", name);
            }
        }

        if (result != -1) {
            *out = row;
            result = 1;
        }
    } else if (rc != SQLITE_DONE) {
        result = fail(store, "lookup conversation");
    }

    sqlite3_reset(store->lookup);
    sqlite3_clear_bindings(store->lookup);

    return result;
}

const char *store_error(const struct store *store) {
    return store->error;
}

int store_dns_save(struct store *store, const struct store_dns_row *row) {
    store->error[0] = '\0';

    if (store->unusable || memchr(row->name, '\0', sizeof row->name) == NULL ||
        row->name[0] == '\0' || row->expires_at < row->observed_at) {
        snprintf(store->error, sizeof store->error, "invalid DNS row or unavailable database");

        return -1;
    }

    int rc = bind_address(store->dns_save, 1, &row->ip);

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(store->dns_save, 2, row->name, -1, SQLITE_TRANSIENT);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int64(store->dns_save, 3, row->observed_at);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int64(store->dns_save, 4, row->expires_at);
    }

    int result;

    if (rc != SQLITE_OK || sqlite3_step(store->dns_save) != SQLITE_DONE) {
        result = fail(store, "save DNS mapping");
    } else {
        result = sqlite3_changes(store->db) != 0;
    }

    sqlite3_reset(store->dns_save);
    sqlite3_clear_bindings(store->dns_save);

    return result;
}

int store_dns_load(struct store *store, int64_t now,
                    int (*visit)(const struct store_dns_row *row, void *user), void *user) {
    store->error[0] = '\0';

    if (sqlite3_bind_int64(store->dns_load, 1, now) != SQLITE_OK) {
        fail(store, "bind DNS load");
        sqlite3_reset(store->dns_load);
        sqlite3_clear_bindings(store->dns_load);

        return -1;
    }

    int rc;
    int result = 0;

    while ((rc = sqlite3_step(store->dns_load)) == SQLITE_ROW) {
        struct store_dns_row row = {
            .observed_at = sqlite3_column_int64(store->dns_load, 2),
            .expires_at = sqlite3_column_int64(store->dns_load, 3)
        };

        if (read_address(store->dns_load, 0, &row.ip) == -1) {
            snprintf(store->error, sizeof store->error, "invalid stored DNS address");
            result = -1;
            break;
        }

        const char *name = (const char *)sqlite3_column_text(store->dns_load, 1);
        const int bytes = sqlite3_column_bytes(store->dns_load, 1);

        if (name == NULL || bytes <= 0 || (size_t)bytes >= sizeof row.name) {
            snprintf(store->error, sizeof store->error, "invalid stored DNS name");
            result = -1;
            break;
        }

        memcpy(row.name, name, (size_t)bytes + 1);

        if (visit(&row, user) == -1) {
            snprintf(store->error, sizeof store->error, "DNS load callback failed");
            result = -1;
            break;
        }
    }

    if (result == 0 && rc != SQLITE_DONE) {
        result = fail(store, "load DNS mappings");
    }

    sqlite3_reset(store->dns_load);
    sqlite3_clear_bindings(store->dns_load);

    return result;
}
