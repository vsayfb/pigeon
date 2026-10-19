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
    CHECK(strstr(error, "schema version 3") != NULL);
    CHECK(sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &statement, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);
    CHECK(sqlite3_column_int(statement, 0) == 2);
    CHECK(sqlite3_finalize(statement) == SQLITE_OK);
    CHECK(sqlite3_close(db) == SQLITE_OK);
    CHECK(unlink(path) == 0);
    CHECK(rmdir(directory) == 0);

    tui_reader_close(NULL);
}

int main(void) {
    test_snapshot_queries_and_refresh();
    test_reader_never_creates_or_migrates();

    puts("tui_model: ok");

    return 0;
}
