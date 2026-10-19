#include "tui/model.h"

#include <sqlite3.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONVERSATION_COLUMNS \
    "us_ip,remote_ip,remote_port,protocol,packets_out,packets_in,bytes_out,bytes_in," \
    "first_seen,last_seen,coalesce(remote_name,''),application"

#define CONVERSATION_FILTER \
    " WHERE (?1='' OR instr(lower(coalesce(remote_name,'')),lower(?1))>0" \
    " OR instr(lower(ip_text(remote_ip)),lower(?1))>0" \
    " OR instr(lower(application),lower(?1))>0)" \
    " AND (?2=0 OR protocol=?2) AND (?3=0 OR length(remote_ip)=?3)" \
    " AND (?7=0 OR application=?8)"

struct live_sample {
    struct flow_key key;
    struct flow_delta observed;
    uint64_t baseline_down;
    uint64_t baseline_up;
    double sampled_at;
    double rate_down;
    double rate_up;
    int valid;
};

struct tui_reader {
    sqlite3 *db;
    sqlite3_stmt *overview;
    sqlite3_stmt *live;
    sqlite3_stmt *top;
    sqlite3_stmt *endpoints;
    sqlite3_stmt *applications;

    double previous_down;
    double previous_up;
    double previous_time;
    int sampled;
    int rates_valid;
    double rate_down;
    double rate_up;
    struct tui_sample history[TUI_HISTORY];
    size_t history_count;
    struct live_sample live_samples[TUI_MAX_ROWS];
    size_t live_sample_count;
    double live_refreshed_at;
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
                              (sqlite3_column_int(version, 0) == 4 || sqlite3_column_int(version, 0) == 5 ||
                               sqlite3_column_int(version, 0) == 6 || sqlite3_column_int(version, 0) == 7);

    const int has_quic = valid_version && sqlite3_column_int(version, 0) >= 6;

    sqlite3_finalize(version);

    if (!valid_version) {
        snprintf(error, TUI_ERROR_LEN, "schema version 4, 5, 6 or 7 required; run pigeon to create or migrate it");
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
    const char *live_format = "SELECT " CONVERSATION_COLUMNS ",%s FROM conversations"
                       CONVERSATION_FILTER
                       " AND (?4=0 OR last_seen>=?5) AND last_seen<=?6"
                       " ORDER BY last_seen DESC,remote_ip,remote_port,protocol,us_ip,application LIMIT 200";
    const char *top_format = "SELECT " CONVERSATION_COLUMNS ",%s FROM conversations"
                      CONVERSATION_FILTER
                      " ORDER BY CASE ?4 WHEN 1 THEN bytes_in WHEN 2 THEN bytes_out"
                      " ELSE cast(bytes_in AS REAL)+bytes_out END DESC,"
                      "last_seen DESC,remote_ip,remote_port,protocol,us_ip,application LIMIT 200";
    char live[2048];
    char top[2048];

    snprintf(live, sizeof live, live_format, has_quic ? "quic" : "0");
    snprintf(top, sizeof top, top_format, has_quic ? "quic" : "0");

    const char *endpoints = "SELECT remote_ip,name,first_seen,last_seen FROM ("
                            "SELECT remote_ip,coalesce(max(remote_name),'') AS name,"
                            "min(first_seen) AS first_seen,max(last_seen) AS last_seen"
                            " FROM conversations GROUP BY remote_ip)"
                            " WHERE (?1='' OR instr(lower(name),lower(?1))>0"
                            " OR instr(lower(ip_text(remote_ip)),lower(?1))>0)"
                            " AND (?2=0 OR length(remote_ip)=?2)"
                            " ORDER BY first_seen DESC,remote_ip LIMIT 200";

    const char *applications = "SELECT application,total(bytes_in),total(bytes_out),"
                               "count(*),count(DISTINCT remote_ip),max(last_seen)"
                               " FROM conversations GROUP BY application"
                               " ORDER BY CASE ?1 WHEN 1 THEN total(bytes_in) WHEN 2 THEN total(bytes_out)"
                               " ELSE total(bytes_in)+total(bytes_out) END DESC,application LIMIT 200";

    if (sqlite3_prepare_v2(reader->db, applications, -1, &reader->applications, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(reader->db, overview, -1, &reader->overview, NULL) != SQLITE_OK ||
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
    sqlite3_finalize(reader->applications);
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

static int bind_application(sqlite3_stmt *statement, const struct tui_options *options) {
    int rc = sqlite3_bind_int(statement, 7, options->application_selected);

    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(statement, 8, options->application, -1, SQLITE_TRANSIENT);
    }

    return rc;
}

static int read_applications(sqlite3_stmt *statement, struct tui_snapshot *snapshot) {
    int rc;

    while ((rc = sqlite3_step(statement)) == SQLITE_ROW) {
        if (snapshot->application_count == TUI_MAX_ROWS) {
            return -1;
        }

        struct tui_application *row = &snapshot->applications[snapshot->application_count++];
        const char *name = (const char *)sqlite3_column_text(statement, 0);
        const int length = sqlite3_column_bytes(statement, 0);

        if (name == NULL || length < 0 || (size_t)length >= sizeof row->name ||
            memchr(name, '\0', (size_t)length) != NULL) {
            return -1;
        }

        memcpy(row->name, name, (size_t)length + 1);
        row->bytes_down = sqlite3_column_double(statement, 1);
        row->bytes_up = sqlite3_column_double(statement, 2);
        row->conversations = (uint64_t)sqlite3_column_int64(statement, 3);
        row->remote_ips = (uint64_t)sqlite3_column_int64(statement, 4);
        row->last_seen = sqlite3_column_int64(statement, 5);
    }

    return rc == SQLITE_DONE ? 0 : -1;
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
        row->quic = sqlite3_column_int(statement, 12);

        if (sqlite3_column_type(statement, 12) != SQLITE_INTEGER ||
            (row->quic != 0 && row->quic != 1) || (row->quic && row->key.protocol != 17)) {
            return -1;
        }
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

        const char *application = (const char *)sqlite3_column_text(statement, 11);
        const int length = sqlite3_column_bytes(statement, 11);

        if (application == NULL || length < 0 || (size_t)length >= sizeof row->key.application ||
            memchr(application, '\0', (size_t)length) != NULL) {
            return -1;
        }

        memcpy(row->key.application, application, (size_t)length + 1);
        snprintf(row->name, sizeof row->name, "%s", name);
    }

    return rc == SQLITE_DONE ? 0 : -1;
}

static void reset_statements(struct tui_reader *reader) {
    sqlite3_stmt *statements[] = {
        reader->overview, reader->live, reader->top, reader->endpoints, reader->applications
    };

    for (size_t i = 0; i < sizeof statements / sizeof statements[0]; i++) {
        sqlite3_reset(statements[i]);
        sqlite3_clear_bindings(statements[i]);
    }
}

static void update_live_rates(struct tui_reader *reader, struct tui_snapshot *snapshot, double now) {
    struct live_sample next[TUI_MAX_ROWS] = { 0 };

    for (size_t i = 0; i < snapshot->live_count; i++) {
        struct tui_conversation *row = &snapshot->live[i];
        struct live_sample *sample = &next[i];
        const struct live_sample *previous = NULL;

        for (size_t j = 0; j < reader->live_sample_count; j++) {
            if (flow_key_equal(&row->key, &reader->live_samples[j].key)) {
                previous = &reader->live_samples[j];
                break;
            }
        }

        const int reset = previous == NULL || now < reader->live_refreshed_at ||
            row->totals.bytes_in < previous->observed.bytes_in ||
            row->totals.bytes_out < previous->observed.bytes_out ||
            row->totals.packets_in < previous->observed.packets_in ||
            row->totals.packets_out < previous->observed.packets_out ||
            row->totals.first_seen != previous->observed.first_seen;

        if (reset) {
            sample->key = row->key;
            sample->baseline_down = row->totals.bytes_in;
            sample->baseline_up = row->totals.bytes_out;
            sample->sampled_at = now;
        } else {
            *sample = *previous;

            const double elapsed = now - sample->sampled_at;

            if (elapsed >= 1.0) {
                /* Subtract integer counters before conversion: small changes
                 * must remain visible even when stored totals exceed 2^53. */
                sample->rate_down = (double)(row->totals.bytes_in - sample->baseline_down) / elapsed;
                sample->rate_up = (double)(row->totals.bytes_out - sample->baseline_up) / elapsed;
                sample->baseline_down = row->totals.bytes_in;
                sample->baseline_up = row->totals.bytes_out;
                sample->sampled_at = now;
                sample->valid = 1;
            }
        }

        sample->observed = row->totals;
        row->rate_down = sample->rate_down;
        row->rate_up = sample->rate_up;
        row->rates_valid = sample->valid;
    }

    memcpy(reader->live_samples, next, snapshot->live_count * sizeof next[0]);
    reader->live_sample_count = snapshot->live_count;
    reader->live_refreshed_at = now;
}

static double live_rate(const struct tui_conversation *row, enum tui_live_sort sort) {
    if (sort == TUI_LIVE_DOWNLOAD) {
        return row->rate_down;
    }

    if (sort == TUI_LIVE_UPLOAD) {
        return row->rate_up;
    }

    return row->rate_down + row->rate_up;
}

static int live_precedes(const struct tui_conversation *a, const struct tui_conversation *b,
                          enum tui_live_sort sort) {
    if (a->rates_valid != b->rates_valid) {
        return a->rates_valid > b->rates_valid;
    }

    if (!a->rates_valid) {
        return 0;
    }

    return live_rate(a, sort) > live_rate(b, sort);
}

static void sort_live(struct tui_snapshot *snapshot, enum tui_live_sort sort) {
    if (sort == TUI_LIVE_RECENCY) {
        return;
    }

    /* Stable insertion sort keeps recency and deterministic key order for
     * equal rates. This list is bounded to 200 rows; baselines stay keyed. */
    for (size_t i = 1; i < snapshot->live_count; i++) {
        const struct tui_conversation row = snapshot->live[i];
        size_t position = i;

        while (position > 0 && live_precedes(&row, &snapshot->live[position - 1], sort)) {
            snapshot->live[position] = snapshot->live[position - 1];
            position--;
        }

        snapshot->live[position] = row;
    }
}

int tui_reader_refresh(struct tui_reader *reader, const struct tui_options *options,
                        int64_t now, double monotonic_seconds, struct tui_snapshot *out,
                        char error[TUI_ERROR_LEN]) {
    if (options->recent_seconds < 0 ||
        (options->protocol != 0 && options->protocol != 6 && options->protocol != 17 &&
         options->protocol != 1 && options->protocol != 58 && options->protocol != 50) ||
        (options->family != 0 && options->family != 4 && options->family != 6) ||
        options->sort < TUI_SORT_TOTAL || options->sort > TUI_SORT_UPLOAD ||
        options->live_sort < TUI_LIVE_RECENCY || options->live_sort > TUI_LIVE_UPLOAD ||
        memchr(options->search, '\0', sizeof options->search) == NULL ||
        (options->application_selected != 0 && options->application_selected != 1) ||
        memchr(options->application, '\0', sizeof options->application) == NULL ||
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

    if (bind_application(reader->live, options) != SQLITE_OK ||
        bind_application(reader->top, options) != SQLITE_OK ||
        sqlite3_bind_int(reader->applications, 1, options->sort) != SQLITE_OK ||
        read_applications(reader->applications, snapshot) == -1 ||
        bind_filters(reader->live, options) != SQLITE_OK ||
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

    update_live_rates(reader, snapshot, monotonic_seconds);
    sort_live(snapshot, options->live_sort);

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
