#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../t.h"
#include "store/store.h"
#include "store/schema.h"

static struct store_row make_row(uint16_t port) {
    const struct store_row row = {
        .key = {
            .us_ip = ip_addr_v4(0xC000020A),
            .remote_ip = ip_addr_v4(0xC6336414),
            .remote_port = port,
            .protocol = 6
        },
        .delta = {
            .packets_out = 3, .packets_in = 2,
            .bytes_out = 100, .bytes_in = 200,
            .first_seen = 1000, .last_seen = 1010
        }
    };

    return row;
}

static struct store *open_memory(void) {
    char error[STORE_ERROR_LEN];
    struct store *store = store_open(":memory:", error);

    if (store == NULL) {
        fprintf(stderr, "%s\n", error);
    }

    CHECK(store != NULL);
    CHECK(error[0] == '\0');

    return store;
}

static void test_totals_and_timestamps(void) {
    struct store *store = open_memory();
    struct store_row row = make_row(443);
    struct store_row found;

    CHECK(store_flush(store, &row, 1) == 0);

    row.delta.first_seen = 1005;
    row.delta.last_seen = 1020;

    CHECK(store_flush(store, &row, 1) == 0);
    CHECK(store_lookup(store, &row.key, &found) == 1);
    CHECK(found.delta.packets_out == 6);
    CHECK(found.delta.packets_in == 4);
    CHECK(found.delta.bytes_out == 200);
    CHECK(found.delta.bytes_in == 400);
    CHECK(found.delta.first_seen == 1000);
    CHECK(found.delta.last_seen == 1020);
    CHECK(found.remote_name[0] == '\0');

    row.delta.first_seen = 990;
    row.delta.last_seen = 1000;

    CHECK(store_flush(store, &row, 1) == 0);
    CHECK(store_lookup(store, &row.key, &found) == 1);
    CHECK(found.delta.first_seen == 990);
    CHECK(found.delta.last_seen == 1020);

    store_close(store);
}

static void test_names_and_independent_keys(void) {
    struct store *store = open_memory();
    struct store_row rows[5];
    struct store_row found;

    for (size_t i = 0; i < 5; i++) {
        rows[i] = make_row(443);
    }

    rows[1].key.us_ip.bytes[3]++;
    rows[2].key.remote_ip.bytes[3]++;
    rows[3].key.remote_port++;
    rows[4].key.protocol = 17;

    CHECK(store_flush(store, rows, 5) == 0);

    for (size_t i = 0; i < 5; i++) {
        CHECK(store_lookup(store, &rows[i].key, &found) == 1);
        CHECK(found.delta.bytes_out == 100);
    }

    strcpy(rows[0].remote_name, "example.test");

    CHECK(store_flush(store, rows, 1) == 0);

    strcpy(rows[0].remote_name, "replacement.test");

    CHECK(store_flush(store, rows, 1) == 0);

    rows[0].remote_name[0] = '\0';

    CHECK(store_flush(store, rows, 1) == 0);
    CHECK(store_lookup(store, &rows[0].key, &found) == 1);
    CHECK(strcmp(found.remote_name, "example.test") == 0);
    CHECK(store_lookup(store, &rows[1].key, &found) == 1);
    CHECK(found.remote_name[0] == '\0');

    /* Names are bound values, including SQL punctuation. */
    strcpy(rows[1].remote_name, "x'); DROP TABLE conversations; --");

    CHECK(store_flush(store, &rows[1], 1) == 0);
    CHECK(store_lookup(store, &rows[1].key, &found) == 1);
    CHECK(strcmp(found.remote_name, rows[1].remote_name) == 0);

    store_close(store);
}

static void test_failed_batch_rolls_back_and_can_retry(void) {
    struct store *store = open_memory();
    struct store_row rows[] = { make_row(443), make_row(80), make_row(53) };
    struct store_row found;

    CHECK(store_flush(store, rows, 1) == 0);

    rows[2].key.protocol = 1;

    CHECK(store_flush(store, rows, 3) == -1);
    CHECK(store_error(store)[0] != '\0');
    CHECK(store_lookup(store, &rows[0].key, &found) == 1);
    CHECK(found.delta.bytes_out == 100);
    CHECK(store_lookup(store, &rows[1].key, &found) == 0);

    rows[2].key.protocol = 17;

    CHECK(store_flush(store, rows, 3) == 0);
    CHECK(store_error(store)[0] == '\0');
    CHECK(store_lookup(store, &rows[0].key, &found) == 1);
    CHECK(found.delta.bytes_out == 200);
    CHECK(store_lookup(store, &rows[1].key, &found) == 1);
    CHECK(found.delta.bytes_out == 100);

    store_close(store);
}

static void test_ranges_and_validation(void) {
    struct store *store = open_memory();
    struct store_row row = make_row(443);
    struct store_row found;

    row.delta.bytes_out = INT64_MAX;
    row.key.us_ip = ip_addr_v4(UINT32_MAX);

    CHECK(store_flush(store, &row, 1) == 0);
    CHECK(store_lookup(store, &row.key, &found) == 1);
    CHECK(ip_addr_v4_value(&found.key.us_ip) == UINT32_MAX);
    CHECK(found.delta.bytes_out == INT64_MAX);

    row.delta.bytes_out = 1;

    CHECK(store_flush(store, &row, 1) == -1);
    CHECK(store_lookup(store, &row.key, &found) == 1);
    CHECK(found.delta.bytes_out == INT64_MAX);
    CHECK(found.delta.packets_out == 3);

    row = make_row(80);
    row.delta.bytes_out = UINT64_MAX;

    CHECK(store_flush(store, &row, 1) == -1);
    CHECK(strstr(store_error(store), "signed 64-bit") != NULL);
    CHECK(store_lookup(store, &row.key, &found) == 0);

    row = make_row(80);
    row.delta.first_seen = row.delta.last_seen + 1;

    CHECK(store_flush(store, &row, 1) == -1);

    row = make_row(80);
    memset(row.remote_name, 'a', sizeof row.remote_name);

    CHECK(store_flush(store, &row, 1) == -1);

    row.remote_name[STORE_NAME_LEN - 1] = '\0';

    CHECK(store_flush(store, &row, 1) == 0);
    CHECK(store_lookup(store, &row.key, &found) == 1);
    CHECK(strlen(found.remote_name) == 253);

    store_close(store);
}

static void test_empty_and_output_ownership(void) {
    struct store *store = open_memory();
    struct store_row row = make_row(443);
    struct store_row found;
    unsigned char before[sizeof found];

    memset(&found, 0xAB, sizeof found);
    memcpy(before, &found, sizeof found);

    CHECK(store_flush(store, NULL, 0) == 0);
    CHECK(store_lookup(store, &row.key, &found) == 0);
    CHECK(memcmp(before, &found, sizeof found) == 0);
    CHECK(store_flush(store, NULL, 1) == -1);

    strcpy(row.remote_name, "example.test");
    memcpy(before, &row, sizeof row);

    CHECK(store_flush(store, &row, 1) == 0);
    CHECK(memcmp(before, &row, sizeof row) == 0);
    CHECK(store_lookup(store, &row.key, &found) == 1);

    store_close(store);

    CHECK(strcmp(found.remote_name, "example.test") == 0);
    CHECK(found.delta.bytes_in == 200);

    store_close(NULL);
}

static int read_scalar(sqlite3 *db, const char *sql) {
    sqlite3_stmt *statement = NULL;

    CHECK(sqlite3_prepare_v2(db, sql, -1, &statement, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);

    const int value = sqlite3_column_int(statement, 0);

    CHECK(sqlite3_finalize(statement) == SQLITE_OK);

    return value;
}

static void test_file_reopen_wal_and_schema_versions(void) {
    char path[] = "/tmp/pigeon-store-XXXXXX";
    const int fd = mkstemp(path);

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    char error[STORE_ERROR_LEN];
    struct store *store = store_open(path, error);
    struct store_row row = make_row(443);
    struct store_row found;

    CHECK(store != NULL);
    CHECK(store_flush(store, &row, 1) == 0);

    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;

    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(read_scalar(db, "PRAGMA user_version") == 3);
    CHECK(sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &statement, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);
    CHECK(strcmp((const char *)sqlite3_column_text(statement, 0), "wal") == 0);
    CHECK(sqlite3_finalize(statement) == SQLITE_OK);
    CHECK(read_scalar(db, "SELECT count(*) FROM conversations") == 1);

    store_close(store);

    store = store_open(path, error);

    CHECK(store != NULL);
    CHECK(store_lookup(store, &row.key, &found) == 1);
    CHECK(found.delta.bytes_out == 100);
    CHECK(store_flush(store, &row, 1) == 0);
    CHECK(read_scalar(db, "SELECT bytes_out FROM conversations") == 200);

    store_close(store);

    CHECK(sqlite3_exec(db, "PRAGMA user_version=99", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(store_open(path, error) == NULL);
    CHECK(strstr(error, "unsupported schema version 99") != NULL);
    CHECK(read_scalar(db, "PRAGMA user_version") == 99);
    CHECK(read_scalar(db, "SELECT bytes_out FROM conversations") == 200);

    CHECK(sqlite3_exec(db, "PRAGMA user_version=0", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(store_open(path, error) == NULL);
    CHECK(strstr(error, "not empty") != NULL);
    CHECK(read_scalar(db, "PRAGMA user_version") == 0);
    CHECK(sqlite3_close(db) == SQLITE_OK);
    CHECK(unlink(path) == 0);
}

static void test_open_failure(void) {
    char path[] = "/tmp/pigeon-store-dir-XXXXXX";
    char error[STORE_ERROR_LEN];

    CHECK(mkdtemp(path) != NULL);
    CHECK(store_open(path, error) == NULL);
    CHECK(error[0] != '\0');
    CHECK(rmdir(path) == 0);
}

static int count_dns(const struct store_dns_row *row, void *user) {
    unsigned *count = user;

    CHECK(row->ip.family == 4 || row->ip.family == 6);
    CHECK(strcmp(row->name, "old.test") == 0 || strcmp(row->name, "ipv6.test") == 0);

    (*count)++;

    return 0;
}

static void test_version_two_migration(void) {
    char path[] = "/tmp/pigeon-store-v2-XXXXXX";
    const int fd = mkstemp(path);
    sqlite3 *db = NULL;
    char error[STORE_ERROR_LEN];

    CHECK(fd != -1);
    CHECK(close(fd) == 0);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, STORE_CONVERSATIONS_V2_SQL STORE_DNS_V2_SQL
                      "INSERT INTO conversations VALUES(3221225994,3325256746,443,6,"
                      "3,2,100,200,100,110,'old.test');"
                      "INSERT INTO dns_cache VALUES(3325256746,'old.test',100,200);"
                      "DROP INDEX dns_cache_expiry;", NULL, NULL, NULL) == SQLITE_OK);

    /* A failed migration restores the version, integer rows and table names. */
    CHECK(store_open(path, error) == NULL);
    CHECK(read_scalar(db, "PRAGMA user_version") == 2);
    CHECK(read_scalar(db, "SELECT typeof(us_ip)='integer' FROM conversations") == 1);
    CHECK(sqlite3_exec(db, "CREATE INDEX dns_cache_expiry ON dns_cache(expires_at)",
                      NULL, NULL, NULL) == SQLITE_OK);

    struct store *store = store_open(path, error);
    struct store_row row;
    struct flow_key key = {
        .us_ip = ip_addr_v4(0xC000020A), .remote_ip = ip_addr_v4(0xC633642A),
        .remote_port = 443, .protocol = 6
    };

    CHECK(store != NULL);
    CHECK(read_scalar(db, "PRAGMA user_version") == 3);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.bytes_out == 100);
    CHECK(row.delta.packets_in == 2);
    CHECK(strcmp(row.remote_name, "old.test") == 0);
    CHECK(read_scalar(db, "SELECT length(us_ip) FROM conversations") == 4);

    unsigned dns_count = 0;

    CHECK(store_dns_load(store, 110, count_dns, &dns_count) == 0);
    CHECK(dns_count == 1);

    CHECK(ip_addr_parse("2001:db8::10", &row.key.us_ip) == 0);
    CHECK(ip_addr_parse("2001:db8::42", &row.key.remote_ip) == 0);

    row.remote_name[0] = '\0';

    CHECK(store_flush(store, &row, 1) == 0);
    CHECK(read_scalar(db, "SELECT count(*) FROM conversations") == 2);

    struct store_dns_row mapping = { .observed_at = 110, .expires_at = 200,
                                      .name = "ipv6.test" };

    CHECK(ip_addr_parse("2001:db8::42", &mapping.ip) == 0);
    CHECK(store_dns_save(store, &mapping) == 1);

    dns_count = 0;

    CHECK(store_dns_load(store, 110, count_dns, &dns_count) == 0);
    CHECK(dns_count == 2);

    store_close(store);

    store = store_open(path, error);

    CHECK(store != NULL);
    CHECK(store_lookup(store, &row.key, &row) == 1);
    CHECK(row.delta.bytes_out == 100);

    store_close(store);

    CHECK(sqlite3_close(db) == SQLITE_OK);
    CHECK(unlink(path) == 0);
}

int main(void) {
    test_totals_and_timestamps();
    test_names_and_independent_keys();
    test_failed_batch_rolls_back_and_can_retry();
    test_ranges_and_validation();
    test_empty_and_output_ownership();
    test_file_reopen_wal_and_schema_versions();
    test_open_failure();
    test_version_two_migration();

    puts("store: ok");

    return 0;
}
