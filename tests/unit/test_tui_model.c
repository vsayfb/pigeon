#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../t.h"
#include "store/schema.h"
#include "store/store.h"
#include "tui/model.h"

static struct store_row make_row(const char *local, const char *remote, uint8_t protocol,
                                  uint64_t down, uint64_t up, int64_t first, int64_t last,
                                  const char *name) {
    struct store_row row = {
        .key.remote_port = 443, .key.protocol = protocol,
        .delta = { .packets_out = 1, .packets_in = 1, .bytes_out = up, .bytes_in = down,
                   .first_seen = first, .last_seen = last }
    };

    CHECK(ip_addr_parse(local, &row.key.us_ip) == 0);
    CHECK(ip_addr_parse(remote, &row.key.remote_ip) == 0);

    snprintf(row.remote_name, sizeof row.remote_name, "%s", name);

    return row;
}

static void test_snapshot_queries_and_refresh(void) {
    char path[] = "/tmp/pigeon-tui-model-XXXXXX";
    const int fd = mkstemp(path);
    char error[TUI_ERROR_LEN];

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    struct store *store = store_open(path, error);
    struct store_row rows[] = {
        make_row("192.0.2.10", "198.51.100.1", 6, 1000, 100, 950, 995, "alpha.test"),
        make_row("192.0.2.10", "198.51.100.1", 17, 100, 200, 900, 990, "alpha.test"),
        make_row("2001:db8::10", "2001:db8::2", 6, 500, 1500, 980, 999, "beta.test"),
        make_row("192.0.2.10", "198.51.100.2", 6, 0, 50, 100, 100, "")
    };

    CHECK(store != NULL);
    CHECK(store_flush(store, rows, 4) == 0);

    struct tui_reader *reader = tui_reader_open(path, error);
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30 };

    CHECK(reader != NULL && snapshot != NULL);
    CHECK(tui_reader_refresh(reader, &options, 1000, 0, snapshot, error) == 0);
    CHECK(snapshot->conversations == 4);
    CHECK(snapshot->remote_ips == 3);
    CHECK(snapshot->bytes_down == 1600);
    CHECK(snapshot->bytes_up == 1850);
    CHECK(snapshot->live_count == 3);
    CHECK(snapshot->live[0].key.us_ip.family == 6);
    CHECK(snapshot->top_count == 4);
    CHECK(strcmp(snapshot->top[0].name, "beta.test") == 0);
    CHECK(snapshot->endpoint_count == 3);
    CHECK(snapshot->endpoints[0].ip.family == 6);
    CHECK(snapshot->endpoints[1].first_seen == 900);
    CHECK(snapshot->rates_valid == 0);

    CHECK(store_flush(store, rows, 1) == 0);
    CHECK(tui_reader_refresh(reader, &options, 1001, 2, snapshot, error) == 0);
    CHECK(snapshot->rates_valid == 1);
    CHECK(snapshot->rate_down == 500);
    CHECK(snapshot->rate_up == 50);
    CHECK(snapshot->history_count == 1);
    CHECK(snapshot->history[0].down == 500);
    CHECK(snapshot->history[0].up == 50);
    CHECK(snapshot->history[0].seconds == 2);

    options.sort = TUI_SORT_DOWNLOAD;

    CHECK(tui_reader_refresh(reader, &options, 1001, 2.1, snapshot, error) == 0);
    CHECK(strcmp(snapshot->top[0].name, "alpha.test") == 0);
    CHECK(snapshot->top[0].key.protocol == 6);
    CHECK(snapshot->history_count == 1);
    CHECK(snapshot->rate_down == 500);

    options.sort = TUI_SORT_UPLOAD;

    CHECK(tui_reader_refresh(reader, &options, 1001, 2.2, snapshot, error) == 0);
    CHECK(strcmp(snapshot->top[0].name, "beta.test") == 0);

    options.family = 6;
    strcpy(options.search, "BETA");

    CHECK(tui_reader_refresh(reader, &options, 1001, 2.3, snapshot, error) == 0);
    CHECK(snapshot->top_count == 1);
    CHECK(snapshot->live_count == 1);
    CHECK(snapshot->endpoint_count == 1);
    CHECK(snapshot->conversations == 4);

    strcpy(options.search, "db8::2");

    CHECK(tui_reader_refresh(reader, &options, 1001, 2.4, snapshot, error) == 0);
    CHECK(snapshot->top_count == 1);

    options.protocol = 17;

    CHECK(tui_reader_refresh(reader, &options, 1001, 2.5, snapshot, error) == 0);
    CHECK(snapshot->top_count == 0);
    CHECK(snapshot->endpoint_count == 1);

    options = (struct tui_options){ .recent_seconds = 0 };

    CHECK(tui_reader_refresh(reader, &options, 1001, 3, snapshot, error) == 0);
    CHECK(snapshot->live_count == 4);

    struct tui_snapshot *before = malloc(sizeof *before);

    CHECK(before != NULL);

    memcpy(before, snapshot, sizeof *before);
    options.recent_seconds = -1;

    CHECK(tui_reader_refresh(reader, &options, 1001, 4, snapshot, error) == -1);
    CHECK(memcmp(before, snapshot, sizeof *before) == 0);

    options.recent_seconds = 30;

    sqlite3 *db = NULL;

    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "DROP TABLE conversations", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(tui_reader_refresh(reader, &options, 1001, 4, snapshot, error) == -1);
    CHECK(error[0] != '\0');
    CHECK(memcmp(before, snapshot, sizeof *before) == 0);
    CHECK(sqlite3_exec(db, STORE_CONVERSATIONS_SQL, NULL, NULL, NULL) == SQLITE_OK);
    CHECK(tui_reader_refresh(reader, &options, 1002, 5, snapshot, error) == 0);
    CHECK(snapshot->conversations == 0);
    CHECK(snapshot->live_count == 0);
    CHECK(snapshot->top_count == 0);
    CHECK(snapshot->endpoint_count == 0);
    CHECK(snapshot->rates_valid == 0);
    CHECK(snapshot->history_count == 0);
    CHECK(sqlite3_close(db) == SQLITE_OK);

    free(before);
    free(snapshot);
    tui_reader_close(reader);
    store_close(store);

    CHECK(unlink(path) == 0);
}

static void test_reader_never_creates_or_migrates(void) {
    char directory[] = "/tmp/pigeon-tui-reader-XXXXXX";
    char path[128];
    char error[TUI_ERROR_LEN];

    CHECK(mkdtemp(directory) != NULL);

    snprintf(path, sizeof path, "%s/missing.db", directory);

    CHECK(tui_reader_open(path, error) == NULL);
    CHECK(access(path, F_OK) == -1);

    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;

    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "PRAGMA user_version=2", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(tui_reader_open(path, error) == NULL);
    CHECK(strstr(error, "schema version 4") != NULL);
    CHECK(sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &statement, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);
    CHECK(sqlite3_column_int(statement, 0) == 2);
    CHECK(sqlite3_finalize(statement) == SQLITE_OK);
    CHECK(sqlite3_close(db) == SQLITE_OK);
    CHECK(unlink(path) == 0);
    CHECK(rmdir(directory) == 0);

    tui_reader_close(NULL);
}

static void test_application_rows_and_search(void) {
    char path[] = "/tmp/pigeon-tui-app-XXXXXX";
    const int fd = mkstemp(path);
    char error[TUI_ERROR_LEN];

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    struct store *store = store_open(path, error);
    struct store_row rows[] = {
        make_row("192.0.2.10", "198.51.100.1", 6, 1000, 100, 950, 995, "alpha.test"),
        make_row("192.0.2.10", "198.51.100.1", 6, 500, 200, 950, 995, "alpha.test"),
        make_row("192.0.2.10", "198.51.100.1", 6, 100, 50, 950, 995, "alpha.test")
    };

    strcpy(rows[0].key.application, "firefox");
    strcpy(rows[1].key.application, "chromium");
    CHECK(store != NULL);
    CHECK(store_flush(store, rows, 3) == 0);

    struct tui_reader *reader = tui_reader_open(path, error);
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30 };

    CHECK(reader != NULL && snapshot != NULL);
    CHECK(tui_reader_refresh(reader, &options, 1000, 0, snapshot, error) == 0);
    CHECK(snapshot->conversations == 3 && snapshot->remote_ips == 1);
    CHECK(snapshot->bytes_down == 1600 && snapshot->bytes_up == 350);
    CHECK(snapshot->top_count == 3 && snapshot->live_count == 3);
    CHECK(snapshot->endpoint_count == 1);
    CHECK(strcmp(snapshot->top[0].key.application, "firefox") == 0);
    CHECK(strcmp(snapshot->top[1].key.application, "chromium") == 0);
    CHECK(snapshot->top[2].key.application[0] == '\0');

    strcpy(options.search, "FIREFOX");
    CHECK(tui_reader_refresh(reader, &options, 1000, 0.1, snapshot, error) == 0);
    CHECK(snapshot->top_count == 1 && snapshot->live_count == 1);
    CHECK(strcmp(snapshot->top[0].key.application, "firefox") == 0);
    CHECK(snapshot->bytes_down == 1600);

    free(snapshot);
    tui_reader_close(reader);
    store_close(store);
    CHECK(unlink(path) == 0);
}

static void test_application_aggregates_and_selection(void) {
    char path[] = "/tmp/pigeon-tui-ranking-XXXXXX";
    const int fd = mkstemp(path);
    char error[TUI_ERROR_LEN];

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    struct store *store = store_open(path, error);
    struct store_row *rows = calloc(209, sizeof *rows);

    CHECK(store != NULL && rows != NULL);

    for (size_t i = 0; i < 205; i++) {
        rows[i] = make_row("192.0.2.10", "198.51.100.1", 6, 1, 2, 950, 995, "bulk.test");
        rows[i].key.remote_port = (uint16_t)(i + 1);
        strcpy(rows[i].key.application, "bulk");
    }

    rows[205] = make_row("192.0.2.10", "198.51.100.1", 6, 100, 100, 950, 995, "alpha.test");
    rows[206] = make_row("192.0.2.10", "198.51.100.1", 17, 50, 1000, 950, 995, "alpha.test");
    rows[207] = make_row("192.0.2.10", "198.51.100.1", 6, 10, 1, 950, 995, "alpha.test");
    rows[208] = make_row("2001:db8::10", "2001:db8::42", 6, 50, 10, 950, 995, "v6.test");
    strcpy(rows[205].key.application, "firefox");
    strcpy(rows[206].key.application, "firefox-nightly");
    strcpy(rows[208].key.application, "firefox");
    CHECK(store_flush(store, rows, 209) == 0);
    free(rows);

    struct tui_reader *reader = tui_reader_open(path, error);
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30 };

    CHECK(reader != NULL && snapshot != NULL);
    CHECK(tui_reader_refresh(reader, &options, 1000, 0, snapshot, error) == 0);
    CHECK(snapshot->top_count == 200);
    CHECK(snapshot->application_count == 4);
    CHECK(strcmp(snapshot->applications[0].name, "firefox-nightly") == 0);
    CHECK(strcmp(snapshot->applications[1].name, "bulk") == 0);
    CHECK(snapshot->applications[1].conversations == 205);
    CHECK(snapshot->applications[1].bytes_down == 205);
    CHECK(snapshot->applications[1].bytes_up == 410);
    CHECK(snapshot->applications[1].remote_ips == 1);
    CHECK(strcmp(snapshot->applications[2].name, "firefox") == 0);
    CHECK(snapshot->applications[2].conversations == 2);
    CHECK(snapshot->applications[2].remote_ips == 2);
    CHECK(snapshot->applications[2].bytes_down == 150);
    CHECK(snapshot->applications[2].last_seen == 995);
    CHECK(snapshot->applications[3].name[0] == '\0');

    options.sort = TUI_SORT_DOWNLOAD;
    CHECK(tui_reader_refresh(reader, &options, 1000, 0.1, snapshot, error) == 0);
    CHECK(strcmp(snapshot->applications[0].name, "bulk") == 0);

    options.sort = TUI_SORT_UPLOAD;
    options.application_selected = 1;
    strcpy(options.application, "firefox");
    CHECK(tui_reader_refresh(reader, &options, 1000, 0.2, snapshot, error) == 0);
    CHECK(snapshot->top_count == 2 && snapshot->live_count == 2);
    CHECK(snapshot->application_count == 4);
    CHECK(strcmp(snapshot->applications[0].name, "firefox-nightly") == 0);
    CHECK(snapshot->bytes_down == 415 && snapshot->bytes_up == 1521);
    CHECK(snapshot->endpoint_count == 2);

    options.family = 6;
    options.protocol = 6;
    CHECK(tui_reader_refresh(reader, &options, 1000, 0.3, snapshot, error) == 0);
    CHECK(snapshot->top_count == 1 && snapshot->top[0].key.remote_ip.family == 6);
    CHECK(snapshot->application_count == 4);

    options.family = options.protocol = 0;
    options.application[0] = '\0';
    CHECK(tui_reader_refresh(reader, &options, 1000, 0.4, snapshot, error) == 0);
    CHECK(snapshot->top_count == 1 && snapshot->live_count == 1);
    CHECK(snapshot->top[0].key.application[0] == '\0');

    strcpy(options.application, "fire'fox");
    CHECK(tui_reader_refresh(reader, &options, 1000, 0.5, snapshot, error) == 0);
    CHECK(snapshot->top_count == 0);
    CHECK(snapshot->application_count == 4);

    options.application_selected = 0;
    strcpy(options.search, "alpha.test");
    CHECK(tui_reader_refresh(reader, &options, 1000, 0.6, snapshot, error) == 0);
    CHECK(snapshot->top_count == 3 && snapshot->live_count == 3);
    CHECK(snapshot->application_count == 4);

    options.application_selected = 2;
    CHECK(tui_reader_refresh(reader, &options, 1000, 0.7, snapshot, error) == -1);
    CHECK(snapshot->application_count == 4);

    free(snapshot);
    tui_reader_close(reader);
    store_close(store);
    CHECK(unlink(path) == 0);
}

static const struct tui_conversation *live_row(const struct tui_snapshot *snapshot,
                                                const char *application, int family) {
    for (size_t i = 0; i < snapshot->live_count; i++) {
        if (strcmp(snapshot->live[i].key.application, application) == 0 &&
            snapshot->live[i].key.us_ip.family == family) {
            return &snapshot->live[i];
        }
    }

    CHECK(0);

    return NULL;
}

static void test_live_rates(void) {
    char path[] = "/tmp/pigeon-tui-rates-XXXXXX";
    const int fd = mkstemp(path);
    char error[TUI_ERROR_LEN];

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    struct store *store = store_open(path, error);
    struct store_row rows[] = {
        make_row("192.0.2.10", "198.51.100.1", 6, 100, 10, 950, 995, "alpha.test"),
        make_row("192.0.2.10", "198.51.100.1", 6, 200, 200, 950, 995, "alpha.test"),
        make_row("2001:db8::10", "2001:db8::42", 17, 300, 30, 950, 995, "v6.test")
    };

    strcpy(rows[0].key.application, "firefox");
    strcpy(rows[1].key.application, "chromium");
    strcpy(rows[2].key.application, "firefox");
    CHECK(store != NULL);
    CHECK(store_flush(store, rows, 3) == 0);

    struct tui_reader *reader = tui_reader_open(path, error);
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30 };

    CHECK(reader != NULL && snapshot != NULL);
    CHECK(tui_reader_refresh(reader, &options, 1000, 10, snapshot, error) == 0);
    CHECK(snapshot->live_count == 3);
    CHECK(snapshot->live[0].key.us_ip.family == 6);
    CHECK(live_row(snapshot, "firefox", 4)->rates_valid == 0);

    rows[0].delta.last_seen = 1002;
    rows[1].delta.last_seen = 1001;
    CHECK(store_flush(store, rows, 3) == 0);
    CHECK(tui_reader_refresh(reader, &options, 1002, 12, snapshot, error) == 0);
    CHECK(strcmp(snapshot->live[0].key.application, "firefox") == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rates_valid == 1);
    CHECK(live_row(snapshot, "firefox", 4)->rate_down == 50);
    CHECK(live_row(snapshot, "firefox", 4)->rate_up == 5);
    CHECK(live_row(snapshot, "chromium", 4)->rate_down == 100);
    CHECK(live_row(snapshot, "firefox", 6)->rate_down == 150);

    options.live_sort = TUI_LIVE_DOWNLOAD;
    CHECK(tui_reader_refresh(reader, &options, 1002, 12.01, snapshot, error) == 0);
    CHECK(snapshot->live[0].key.us_ip.family == 6);
    CHECK(snapshot->live[0].rate_down == 150);
    CHECK(strcmp(snapshot->live[1].key.application, "chromium") == 0);

    options.live_sort = TUI_LIVE_UPLOAD;
    CHECK(tui_reader_refresh(reader, &options, 1002, 12.02, snapshot, error) == 0);
    CHECK(strcmp(snapshot->live[0].key.application, "chromium") == 0);
    CHECK(snapshot->live[0].rate_up == 100);
    CHECK(snapshot->live[1].key.us_ip.family == 6);

    options.live_sort = TUI_LIVE_TOTAL;
    CHECK(tui_reader_refresh(reader, &options, 1002, 12.03, snapshot, error) == 0);
    CHECK(strcmp(snapshot->live[0].key.application, "chromium") == 0);
    CHECK(snapshot->live[1].key.us_ip.family == 6);
    CHECK(snapshot->live[2].key.us_ip.family == 4);
    CHECK(strcmp(snapshot->top[0].key.application, "chromium") == 0);

    options.live_sort = TUI_LIVE_RECENCY;
    CHECK(tui_reader_refresh(reader, &options, 1002, 12.04, snapshot, error) == 0);
    CHECK(strcmp(snapshot->live[0].key.application, "firefox") == 0);
    CHECK(snapshot->live[0].key.us_ip.family == 4);

    options.live_sort = TUI_LIVE_DOWNLOAD;

    rows[0].delta.bytes_in = 50;
    rows[0].delta.bytes_out = 5;
    CHECK(store_flush(store, rows, 1) == 0);
    CHECK(tui_reader_refresh(reader, &options, 1002, 12.2, snapshot, error) == 0);
    CHECK(live_row(snapshot, "chromium", 4)->rate_down == 100);
    CHECK(tui_reader_refresh(reader, &options, 1002, 13, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rate_down == 50);
    CHECK(live_row(snapshot, "chromium", 4)->rates_valid == 1);
    CHECK(live_row(snapshot, "chromium", 4)->rate_down == 0);

    options.application_selected = 1;
    strcpy(options.application, "firefox");
    CHECK(tui_reader_refresh(reader, &options, 1002, 13.1, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rate_down == 50);

    strcpy(options.application, "chromium");
    CHECK(tui_reader_refresh(reader, &options, 1002, 14, snapshot, error) == 0);
    CHECK(live_row(snapshot, "chromium", 4)->rates_valid == 0);
    CHECK(tui_reader_refresh(reader, &options, 1002, 15, snapshot, error) == 0);
    CHECK(live_row(snapshot, "chromium", 4)->rates_valid == 1);
    CHECK(live_row(snapshot, "chromium", 4)->rate_down == 0);

    options.application_selected = 0;
    CHECK(tui_reader_refresh(reader, &options, 1002, 16, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rates_valid == 0);
    CHECK(strcmp(snapshot->live[0].key.application, "chromium") == 0);
    CHECK(snapshot->live[0].rates_valid == 1 && snapshot->live[0].rate_down == 0);

    sqlite3 *db = NULL;

    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "UPDATE conversations SET bytes_in=1,bytes_out=1,packets_in=1,packets_out=1"
                      " WHERE application='firefox' AND length(us_ip)=4", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(tui_reader_refresh(reader, &options, 1002, 16.2, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rates_valid == 0);
    CHECK(tui_reader_refresh(reader, &options, 1002, 17.2, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rates_valid == 1);
    CHECK(live_row(snapshot, "firefox", 4)->rate_down == 0);
    CHECK(strcmp(snapshot->live[0].key.application, "firefox") == 0);
    CHECK(snapshot->live[0].key.us_ip.family == 4);

    CHECK(sqlite3_exec(db, "UPDATE conversations SET bytes_in=9007199254740992,bytes_out=9007199254740992"
                      " WHERE application='firefox' AND length(us_ip)=4", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(tui_reader_refresh(reader, &options, 1002, 19, snapshot, error) == 0);
    CHECK(sqlite3_exec(db, "UPDATE conversations SET bytes_in=bytes_in+1,bytes_out=bytes_out+3"
                      " WHERE application='firefox' AND length(us_ip)=4", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(tui_reader_refresh(reader, &options, 1002, 20, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rate_down == 1);
    CHECK(live_row(snapshot, "firefox", 4)->rate_up == 3);

    CHECK(tui_reader_refresh(reader, &options, 1002, 19.5, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rates_valid == 0);
    CHECK(tui_reader_refresh(reader, &options, 1002, 20.5, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rates_valid == 1);

    CHECK(sqlite3_exec(db, "ALTER TABLE conversations RENAME TO hidden", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(tui_reader_refresh(reader, &options, 1002, 21, snapshot, error) == -1);
    CHECK(sqlite3_exec(db, "ALTER TABLE hidden RENAME TO conversations;"
                      "UPDATE conversations SET bytes_in=bytes_in+2"
                      " WHERE application='firefox' AND length(us_ip)=4", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(tui_reader_refresh(reader, &options, 1002, 22.5, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rate_down == 1);

    CHECK(tui_reader_refresh(reader, &options, 1100, 120, snapshot, error) == 0);
    CHECK(snapshot->live_count == 0);
    options.recent_seconds = 0;
    CHECK(tui_reader_refresh(reader, &options, 1100, 121, snapshot, error) == 0);
    CHECK(live_row(snapshot, "firefox", 4)->rates_valid == 0);

    options.live_sort = (enum tui_live_sort)99;
    CHECK(tui_reader_refresh(reader, &options, 1100, 122, snapshot, error) == -1);
    CHECK(snapshot->live_count == 3);

    CHECK(sqlite3_close(db) == SQLITE_OK);
    free(snapshot);
    tui_reader_close(reader);
    store_close(store);
    CHECK(unlink(path) == 0);
}

static void test_icmp_filters(void) {
    char path[] = "/tmp/pigeon-tui-icmp-XXXXXX";
    const int fd = mkstemp(path);
    char error[TUI_ERROR_LEN];

    CHECK(fd != -1 && close(fd) == 0);

    struct store *store = store_open(path, error);
    struct store_row rows[] = {
        make_row("192.0.2.10", "198.51.100.42", 1, 4, 4, 100, 110, "ping.test"),
        make_row("2001:db8::10", "2001:db8::42", 58, 4, 4, 100, 110, "ping6.test")
    };

    rows[0].key.remote_port = rows[1].key.remote_port = 0;
    CHECK(store != NULL && store_flush(store, rows, 2) == 0);

    struct tui_reader *reader = tui_reader_open(path, error);
    struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
    struct tui_options options = { .recent_seconds = 30, .protocol = 1 };

    CHECK(reader != NULL && snapshot != NULL);
    CHECK(tui_reader_refresh(reader, &options, 110, 0, snapshot, error) == 0);
    CHECK(snapshot->live_count == 1 && snapshot->top_count == 1);
    CHECK(snapshot->live[0].key.protocol == 1 && snapshot->live[0].key.remote_port == 0);
    options.protocol = 58;
    CHECK(tui_reader_refresh(reader, &options, 111, 2, snapshot, error) == 0);
    CHECK(snapshot->live_count == 1 && snapshot->top[0].key.protocol == 58);

    free(snapshot);
    tui_reader_close(reader);
    store_close(store);
    CHECK(unlink(path) == 0);
}

static void test_quic_and_legacy_versions(void) {
    for (int version = 4; version <= 6; version++) {
        char path[] = "/tmp/pigeon-tui-quic-XXXXXX";
        const int fd = mkstemp(path);
        char error[TUI_ERROR_LEN];
        sqlite3 *db = NULL;

        CHECK(fd != -1 && close(fd) == 0);
        CHECK(sqlite3_open(path, &db) == SQLITE_OK);
        CHECK(sqlite3_exec(db, version == 4 ? STORE_CONVERSATIONS_V4_SQL : STORE_CONVERSATIONS_V5_SQL,
                           NULL, NULL, NULL) == SQLITE_OK);
        CHECK(sqlite3_exec(db, STORE_DNS_SCHEMA_SQL
                          "INSERT INTO conversations VALUES(X'C000020A',X'C6336414',443,17,"
                          "1,1,100,200,100,110,NULL,'');", NULL, NULL, NULL) == SQLITE_OK);

        const char *sql = version == 4 ? "PRAGMA user_version=4;" :
                          version == 5 ? "PRAGMA user_version=5;" : STORE_MIGRATE_V5_SQL;

        CHECK(sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK);
        if (version == 6) {
            CHECK(sqlite3_exec(db, "UPDATE conversations SET quic=1", NULL, NULL, NULL) == SQLITE_OK);
        }

        struct tui_reader *reader = tui_reader_open(path, error);
        struct tui_snapshot *snapshot = calloc(1, sizeof *snapshot);
        struct tui_options options = { .protocol = 17, .recent_seconds = 30 };

        CHECK(reader != NULL && snapshot != NULL);
        CHECK(tui_reader_refresh(reader, &options, 110, 0, snapshot, error) == 0);
        CHECK(snapshot->live_count == 1 && snapshot->top_count == 1);
        CHECK(snapshot->live[0].quic == (version == 6));
        CHECK(snapshot->top[0].key.protocol == 17 && snapshot->top[0].totals.bytes_out == 100);
        free(snapshot);
        tui_reader_close(reader);
        CHECK(sqlite3_close(db) == SQLITE_OK);
        CHECK(unlink(path) == 0);
    }
}

int main(void) {
    test_snapshot_queries_and_refresh();
    test_reader_never_creates_or_migrates();
    test_application_rows_and_search();
    test_application_aggregates_and_selection();
    test_live_rates();
    test_icmp_filters();
    test_quic_and_legacy_versions();

    puts("tui_model: ok");

    return 0;
}
