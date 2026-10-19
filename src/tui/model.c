#include "tui/model.h"

#include <sqlite3.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONVERSATION_COLUMNS \
    "us_ip,remote_ip,remote_port,protocol,packets_out,packets_in,bytes_out,bytes_in," \
    "first_seen,last_seen,coalesce(remote_name,'')"

#define CONVERSATION_FILTER \
    " WHERE (?1='' OR instr(lower(coalesce(remote_name,'')),lower(?1))>0" \
    " OR instr(lower(ip_text(remote_ip)),lower(?1))>0)" \
    " AND (?2=0 OR protocol=?2) AND (?3=0 OR length(remote_ip)=?3)"

struct tui_reader {
    sqlite3 *db;
    sqlite3_stmt *overview;
    sqlite3_stmt *live;
    sqlite3_stmt *top;
    sqlite3_stmt *endpoints;

    double previous_down;
    double previous_up;
    double previous_time;
    int sampled;
    int rates_valid;
    double rate_down;
    double rate_up;
    struct tui_sample history[TUI_HISTORY];
    size_t history_count;
};

static int read_address(sqlite3_stmt *statement, int column, struct ip_addr *out) {
    const int length = sqlite3_column_bytes(statement, column);
    const void *bytes = sqlite3_column_blob(statement, column);

    if (sqlite3_column_type(statement, column) != SQLITE_BLOB || bytes == NULL ||
        (length != 4 && length != 16)) {
        return -1;
    }

    out->family = length == 4 ? 4 : 6;
    memcpy(out->bytes, bytes, (size_t)length);

    return 0;
}

static void sql_ip_text(sqlite3_context *context, int count, sqlite3_value **values) {
    (void)count;

    const int length = sqlite3_value_bytes(values[0]);
    const void *bytes = sqlite3_value_blob(values[0]);
    struct ip_addr address = { 0 };
    char text[IP_ADDR_STR_LEN];

    if (bytes == NULL || (length != 4 && length != 16)) {
        sqlite3_result_text(context, "", 0, SQLITE_STATIC);

        return;
    }

    address.family = length == 4 ? 4 : 6;
    memcpy(address.bytes, bytes, (size_t)length);
    sqlite3_result_text(context, ip_addr_str(&address, text), -1, SQLITE_TRANSIENT);
}

static int failure(struct tui_reader *reader, char error[TUI_ERROR_LEN], const char *operation) {
    snprintf(error, TUI_ERROR_LEN, "%s: %s", operation, sqlite3_errmsg(reader->db));

    return -1;
}

struct tui_reader *tui_reader_open(const char *path, char error[TUI_ERROR_LEN]) {
    struct tui_reader *reader = calloc(1, sizeof *reader);

    if (reader == NULL) {
        snprintf(error, TUI_ERROR_LEN, "viewer allocation failed");

        return NULL;
    }

    if (sqlite3_open_v2(path, &reader->db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        failure(reader, error, "open read-only database");
        goto error;
    }

    sqlite3_stmt *version = NULL;

    if (sqlite3_prepare_v2(reader->db, "PRAGMA user_version", -1, &version, NULL) != SQLITE_OK) {
        failure(reader, error, "read schema version");
        goto error;
    }

    const int valid_version = sqlite3_step(version) == SQLITE_ROW &&
                              sqlite3_column_int(version, 0) == 3;

    sqlite3_finalize(version);

    if (!valid_version) {
        snprintf(error, TUI_ERROR_LEN, "schema version 3 required; run pigeon to create or migrate it");
        goto error;
    }

    if (sqlite3_db_readonly(reader->db, "main") != 1 ||
        sqlite3_busy_timeout(reader->db, 150) != SQLITE_OK ||
        sqlite3_create_function_v2(reader->db, "ip_text", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                   NULL, sql_ip_text, NULL, NULL, NULL) != SQLITE_OK) {
        failure(reader, error, "configure reader");
        goto error;
    }

    const char *overview = "SELECT count(*),count(DISTINCT remote_ip),"
                           "total(bytes_in),total(bytes_out),max(last_seen) FROM conversations";
    const char *live = "SELECT " CONVERSATION_COLUMNS " FROM conversations"
                       CONVERSATION_FILTER
                       " AND (?4=0 OR last_seen>=?5) AND last_seen<=?6"
                       " ORDER BY last_seen DESC,remote_ip,remote_port,protocol,us_ip LIMIT 200";
    const char *top = "SELECT " CONVERSATION_COLUMNS " FROM conversations"
                      CONVERSATION_FILTER
                      " ORDER BY CASE ?4 WHEN 1 THEN bytes_in WHEN 2 THEN bytes_out"
                      " ELSE cast(bytes_in AS REAL)+bytes_out END DESC,"
                      "last_seen DESC,remote_ip,remote_port,protocol,us_ip LIMIT 200";
    const char *endpoints = "SELECT remote_ip,name,first_seen,last_seen FROM ("
                            "SELECT remote_ip,coalesce(max(remote_name),'') AS name,"
                            "min(first_seen) AS first_seen,max(last_seen) AS last_seen"
                            " FROM conversations GROUP BY remote_ip)"
                            " WHERE (?1='' OR instr(lower(name),lower(?1))>0"
                            " OR instr(lower(ip_text(remote_ip)),lower(?1))>0)"
                            " AND (?2=0 OR length(remote_ip)=?2)"
                            " ORDER BY first_seen DESC,remote_ip LIMIT 200";

    if (sqlite3_prepare_v2(reader->db, overview, -1, &reader->overview, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(reader->db, live, -1, &reader->live, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(reader->db, top, -1, &reader->top, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(reader->db, endpoints, -1, &reader->endpoints, NULL) != SQLITE_OK) {
        failure(reader, error, "prepare dashboard queries");
        goto error;
    }

    error[0] = '\0';

    return reader;

error:
    tui_reader_close(reader);

    return NULL;
}

void tui_reader_close(struct tui_reader *reader) {
    if (reader == NULL) {
        return;
    }

    sqlite3_finalize(reader->overview);
    sqlite3_finalize(reader->live);
    sqlite3_finalize(reader->top);
    sqlite3_finalize(reader->endpoints);
    sqlite3_close(reader->db);
    free(reader);
}

static int bind_filters(sqlite3_stmt *statement, const struct tui_options *options) {
    int rc = sqlite3_bind_text(statement, 1, options->search, -1, SQLITE_TRANSIENT);

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(statement, 2, options->protocol);
    }

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(statement, 3, options->family == 4 ? 4 : options->family == 6 ? 16 : 0);
    }

    return rc;
}

static int read_conversations(sqlite3_stmt *statement, struct tui_conversation *rows, size_t *count) {
    int rc;

    while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
        if (*count == TUI_MAX_ROWS) {
            return -1;
        }

        struct tui_conversation *row = &rows[(*count)++];

        if (read_address(statement, 0, &row->key.us_ip) == -1 ||
            read_address(statement, 1, &row->key.remote_ip) == -1) {
            return -1;
        }

        row->key.remote_port = (uint16_t)sqlite3_column_int(statement, 2);
        row->key.protocol = (uint8_t)sqlite3_column_int(statement, 3);
        row->totals.packets_out = (uint64_t)sqlite3_column_int64(statement, 4);
        row->totals.packets_in = (uint64_t)sqlite3_column_int64(statement, 5);
        row->totals.bytes_out = (uint64_t)sqlite3_column_int64(statement, 6);
        row->totals.bytes_in = (uint64_t)sqlite3_column_int64(statement, 7);
        row->totals.first_seen = sqlite3_column_int64(statement, 8);
        row->totals.last_seen = sqlite3_column_int64(statement, 9);

        const char *name = (const char *)sqlite3_column_text(statement, 10);

        if (name == NULL) {
            return -1;
        }

        snprintf(row->name, sizeof row->name, "%s", name);
    }

    return rc == SQLITE_DONE ? 0 : -1;
}

static void reset_statements(struct tui_reader *reader) {
    sqlite3_stmt *statements[] = { reader->overview, reader->live, reader->top, reader->endpoints };

    for (size_t i = 0; i < sizeof statements / sizeof statements[0]; i++) {
        sqlite3_reset(statements[i]);
        sqlite3_clear_bindings(statements[i]);
    }
}

int tui_reader_refresh(struct tui_reader *reader, const struct tui_options *options,
                        int64_t now, double monotonic_seconds, struct tui_snapshot *out,
                        char error[TUI_ERROR_LEN]) {
    if (options->recent_seconds < 0 ||
        (options->protocol != 0 && options->protocol != 6 && options->protocol != 17) ||
        (options->family != 0 && options->family != 4 && options->family != 6) ||
        options->sort < TUI_SORT_TOTAL || options->sort > TUI_SORT_UPLOAD ||
        memchr(options->search, '\0', sizeof options->search) == NULL ||
        !isfinite(monotonic_seconds) || monotonic_seconds < 0) {
        snprintf(error, TUI_ERROR_LEN, "invalid dashboard options or clock");

        return -1;
    }

    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);

    if (snapshot == NULL) {
        snprintf(error, TUI_ERROR_LEN, "snapshot allocation failed");

        return -1;
    }

    if (sqlite3_exec(reader->db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK) {
        failure(reader, error, "begin read snapshot");
        free(snapshot);

        return -1;
    }

    if (sqlite3_step(reader->overview) != SQLITE_ROW) {
        goto error;
    }

    snapshot->conversations = (uint64_t)sqlite3_column_int64(reader->overview, 0);
    snapshot->remote_ips = (uint64_t)sqlite3_column_int64(reader->overview, 1);
    snapshot->bytes_down = sqlite3_column_double(reader->overview, 2);
    snapshot->bytes_up = sqlite3_column_double(reader->overview, 3);
    snapshot->has_packets = sqlite3_column_type(reader->overview, 4) != SQLITE_NULL;
    snapshot->latest_packet = sqlite3_column_int64(reader->overview, 4);
    snapshot->loaded_at = now;
    sqlite3_reset(reader->overview);

    const int64_t cutoff = now < INT64_MIN + options->recent_seconds
                           ? INT64_MIN : now - options->recent_seconds;

    if (bind_filters(reader->live, options) != SQLITE_OK ||
        sqlite3_bind_int(reader->live, 4, options->recent_seconds) != SQLITE_OK ||
        sqlite3_bind_int64(reader->live, 5, cutoff) != SQLITE_OK ||
        sqlite3_bind_int64(reader->live, 6, now) != SQLITE_OK ||
        read_conversations(reader->live, snapshot->live, &snapshot->live_count) == -1 ||
        bind_filters(reader->top, options) != SQLITE_OK ||
        sqlite3_bind_int(reader->top, 4, options->sort) != SQLITE_OK ||
        read_conversations(reader->top, snapshot->top, &snapshot->top_count) == -1) {
        goto error;
    }

    if (sqlite3_bind_text(reader->endpoints, 1, options->search, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_int(reader->endpoints, 2, options->family == 4 ? 4 : options->family == 6 ? 16 : 0)
        != SQLITE_OK) {
        goto error;
    }

    int rc;

    while ((rc = sqlite3_step(reader->endpoints)) == SQLITE_ROW) {
        struct tui_endpoint *row = &snapshot->endpoints[snapshot->endpoint_count++];

        if (read_address(reader->endpoints, 0, &row->ip) == -1) {
            goto error;
        }

        const char *name = (const char *)sqlite3_column_text(reader->endpoints, 1);

        if (name == NULL) {
            goto error;
        }

        snprintf(row->name, sizeof row->name, "%s", name);
        row->first_seen = sqlite3_column_int64(reader->endpoints, 2);
        row->last_seen = sqlite3_column_int64(reader->endpoints, 3);
    }

    if (rc != SQLITE_DONE) {
        goto error;
    }

    reset_statements(reader);

    if (sqlite3_exec(reader->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        goto error;
    }

    if (!reader->sampled || monotonic_seconds < reader->previous_time ||
        snapshot->bytes_down < reader->previous_down || snapshot->bytes_up < reader->previous_up) {
        reader->previous_down = snapshot->bytes_down;
        reader->previous_up = snapshot->bytes_up;
        reader->previous_time = monotonic_seconds;
        reader->sampled = 1;
        reader->rates_valid = 0;
        reader->history_count = 0;
    } else if (monotonic_seconds - reader->previous_time >= 1.0) {
        const double elapsed = monotonic_seconds - reader->previous_time;

        reader->rate_down = (snapshot->bytes_down - reader->previous_down) / elapsed;
        reader->rate_up = (snapshot->bytes_up - reader->previous_up) / elapsed;
        reader->rates_valid = 1;
        reader->previous_down = snapshot->bytes_down;
        reader->previous_up = snapshot->bytes_up;
        reader->previous_time = monotonic_seconds;

        if (reader->history_count == TUI_HISTORY) {
            memmove(reader->history, reader->history + 1, (TUI_HISTORY - 1) * sizeof reader->history[0]);
            reader->history_count--;
        }

        reader->history[reader->history_count++] = (struct tui_sample) {
            .down = reader->rate_down,
            .up = reader->rate_up,
            .seconds = elapsed
        };
    }

    snapshot->rate_down = reader->rate_down;
    snapshot->rate_up = reader->rate_up;
    snapshot->rates_valid = reader->rates_valid;
    snapshot->history_count = reader->history_count;
    memcpy(snapshot->history, reader->history, sizeof snapshot->history);
    *out = *snapshot;
    free(snapshot);
    error[0] = '\0';

    return 0;

error:
    failure(reader, error, "refresh dashboard");
    reset_statements(reader);
    sqlite3_exec(reader->db, "ROLLBACK", NULL, NULL, NULL);
    free(snapshot);

    return -1;
}
