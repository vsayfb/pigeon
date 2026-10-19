#include <errno.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../t.h"
#include "dns/dns_cache.h"
#include "flow/flow.h"
#include "store/schema.h"
#include "store/store.h"

#define LOCAL_IP UINT32_C(0xC000020A)
#define REMOTE_IP UINT32_C(0xC633642A)

static struct dns_answer answer_for(uint32_t ip, const char *name, uint32_t ttl) {
    struct dns_answer answer = { .ip = ip_addr_v4(ip), .ttl = ttl };

    strcpy(answer.name, name);

    return answer;
}

static struct store *open_memory(void) {
    char error[STORE_ERROR_LEN];
    struct store *store = store_open(":memory:", error);

    CHECK(store != NULL);

    return store;
}

static void test_ttl_replacement_and_capacity(void) {
    struct store *store = open_memory();
    struct dns_cache *cache = dns_cache_create(store, 2, 100);
    struct dns_answer answer = answer_for(REMOTE_IP, "first.test", 30);

    CHECK(cache != NULL);
    CHECK(dns_cache_update(cache, &answer, 100) == 1);
    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 99) == NULL);
    CHECK(strcmp(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 129), "first.test") == 0);
    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 130) == NULL);

    answer = answer_for(REMOTE_IP, "second.test", 60);

    CHECK(dns_cache_update(cache, &answer, 110) == 1);
    CHECK(dns_cache_update(cache, &answer, 109) == 0);
    CHECK(strcmp(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 110), "second.test") == 0);

    answer.ttl = 0;

    CHECK(dns_cache_update(cache, &answer, 111) == 1);
    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 111) == NULL);

    answer = answer_for(REMOTE_IP + 256, "collision.test", 60);

    CHECK(dns_cache_update(cache, &answer, 112) == 1);

    answer = answer_for(REMOTE_IP + 512, "third.test", 60);

    CHECK(dns_cache_update(cache, &answer, 113) == 1);
    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 113) == NULL);
    CHECK(strcmp(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP + 256), 113), "collision.test") == 0);

    answer = answer_for(REMOTE_IP + 768, "fourth.test", 60);

    CHECK(dns_cache_update(cache, &answer, 114) == 1);
    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP + 256), 114) == NULL);

    dns_cache_expire(cache, 174);

    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP + 512), 174) == NULL);
    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP + 768), 174) == NULL);

    dns_cache_destroy(cache);
    store_close(store);
}

static void test_persistent_reload(void) {
    char path[] = "/tmp/pigeon-dns-reload-XXXXXX";
    const int fd = mkstemp(path);

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    char error[STORE_ERROR_LEN];
    struct store *store = store_open(path, error);
    struct dns_cache *cache = dns_cache_create(store, 8, 100);
    struct dns_answer answer = answer_for(REMOTE_IP, "saved.test", 60);

    CHECK(cache != NULL);
    CHECK(dns_cache_update(cache, &answer, 100) == 1);

    dns_cache_destroy(cache);
    store_close(store);

    store = store_open(path, error);
    cache = dns_cache_create(store, 8, 110);

    CHECK(cache != NULL);
    CHECK(strcmp(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 110), "saved.test") == 0);

    dns_cache_destroy(cache);

    cache = dns_cache_create(store, 8, 160);

    CHECK(cache != NULL);
    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 160) == NULL);

    dns_cache_destroy(cache);
    store_close(store);

    CHECK(unlink(path) == 0);
}

static struct packet_view service_packet(void) {
    struct packet_view packet = { 0 };

    packet.kind = PACKET_TCP;
    packet.ip.src = LOCAL_IP;
    packet.ip.dst = REMOTE_IP;
    packet.ip.protocol = IP_PROTO_TCP;
    packet.transport.tcp.src_port = 49152;
    packet.transport.tcp.dst_port = 443;
    packet.transport.tcp.payload_wire_len = 10;

    return packet;
}

static void test_flow_naming(int dns_first) {
    struct store *store = open_memory();
    struct dns_cache *cache = dns_cache_create(store, 8, 100);
    struct flow *flow = flow_create(LOCAL_IP, 4, 8);
    const struct packet_view packet = service_packet();
    struct dns_answer answer = answer_for(REMOTE_IP, "service.test", 60);
    struct store_row row;

    const struct flow_key key = {
        .us_ip = ip_addr_v4(LOCAL_IP), .remote_ip = ip_addr_v4(REMOTE_IP),
        .remote_port = 443, .protocol = IP_PROTO_TCP
    };

    CHECK(cache != NULL && flow != NULL);

    flow_set_store(flow, store);
    flow_set_dns_cache(flow, cache);

    if (dns_first) {
        CHECK(dns_cache_update(cache, &answer, 100) == 1);
    }

    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_tick(flow, 100) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 1);

    if (!dns_first) {
        CHECK(row.remote_name[0] == '\0');
        CHECK(dns_cache_update(cache, &answer, 101) == 1);
        CHECK(flow_tick(flow, 101) == 0);
    }

    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(strcmp(row.remote_name, "service.test") == 0);
    CHECK(row.delta.packets_out == 1);
    CHECK(row.delta.bytes_out == 10);
    CHECK(strcmp(flow_entry_name(flow_find(flow, &key)), "service.test") == 0);

    answer = answer_for(REMOTE_IP, "replacement.test", 60);

    CHECK(dns_cache_update(cache, &answer, 102) == 1);
    CHECK(flow_tick(flow, 102) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(strcmp(row.remote_name, "service.test") == 0);

    flow_destroy(flow);
    dns_cache_destroy(cache);
    store_close(store);
}

static void test_failure_preserves_memory_and_migration(void) {
    char path[] = "/tmp/pigeon-dns-migrate-XXXXXX";
    const int fd = mkstemp(path);

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    sqlite3 *db = NULL;

    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, STORE_CONVERSATIONS_V2_SQL "PRAGMA user_version=1;"
                      "INSERT INTO conversations VALUES(3221225994,3325256746,443,6,"
                      "3,2,100,200,100,110,'original.test')", NULL, NULL, NULL) == SQLITE_OK);

    char error[STORE_ERROR_LEN];
    struct store *store = store_open(path, error);
    struct dns_cache *cache = dns_cache_create(store, 8, 100);
    struct dns_answer answer = answer_for(REMOTE_IP, "old.test", 60);
    struct store_row row;

    const struct flow_key key = {
        .us_ip = ip_addr_v4(LOCAL_IP), .remote_ip = ip_addr_v4(REMOTE_IP),
        .remote_port = 443, .protocol = IP_PROTO_TCP
    };

    CHECK(cache != NULL);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.bytes_out == 100);
    CHECK(strcmp(row.remote_name, "original.test") == 0);
    CHECK(dns_cache_update(cache, &answer, 100) == 1);
    CHECK(sqlite3_exec(db, "CREATE TRIGGER reject_dns BEFORE INSERT ON dns_cache "
                      "BEGIN SELECT RAISE(ABORT,'test failure'); END", NULL, NULL, NULL)
          == SQLITE_OK);

    strcpy(answer.name, "new.test");

    CHECK(dns_cache_update(cache, &answer, 110) == -1);
    CHECK(errno == EIO);
    CHECK(strcmp(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 110), "old.test") == 0);

    answer.ip.bytes[3]++;

    CHECK(dns_cache_update(cache, &answer, 110) == -1);
    CHECK(dns_cache_lookup(cache, answer.ip, 110) == NULL);
    CHECK(sqlite3_exec(db, "DROP TRIGGER reject_dns", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(dns_cache_update(cache, &answer, 110) == 1);

    dns_cache_destroy(cache);
    store_close(store);

    store = store_open(path, error);
    cache = dns_cache_create(store, 8, 111);

    CHECK(cache != NULL);
    CHECK(strcmp(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 111), "old.test") == 0);
    CHECK(strcmp(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP + 1), 111), "new.test") == 0);

    dns_cache_destroy(cache);
    store_close(store);

    CHECK(sqlite3_close(db) == SQLITE_OK);
    CHECK(unlink(path) == 0);
}

static void test_observe_filters_and_partial_reply(void) {
    struct store *store = open_memory();
    struct dns_cache *cache = dns_cache_create(store, 8, 100);
    uint8_t data[] = {
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
        1, 'a', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1,
        0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 42
    };

    struct packet_view packet = { 0 };

    packet.kind = PACKET_UDP;
    packet.ip.dst = LOCAL_IP;
    packet.transport.udp.src_port = 53;
    packet.transport.udp.payload = data;
    packet.transport.udp.payload_len = sizeof data;

    CHECK(cache != NULL);
    CHECK(dns_cache_observe(cache, &packet, LOCAL_IP, 100) == 1);
    CHECK(strcmp(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 100), "a.test") == 0);

    packet.transport.udp.src_port = 443;

    CHECK(dns_cache_observe(cache, &packet, LOCAL_IP, 101) == 0);

    packet.transport.udp.src_port = 53;
    packet.ip.dst++;

    CHECK(dns_cache_observe(cache, &packet, LOCAL_IP, 101) == 0);

    packet.ip.dst = LOCAL_IP;
    data[2] = 1;

    CHECK(dns_cache_observe(cache, &packet, LOCAL_IP, 101) == 0);

    data[2] = 0x81;
    data[7] = 2;

    CHECK(dns_cache_observe(cache, &packet, LOCAL_IP, 101) == 1);

    data[12] = 0xC0;
    data[13] = 12;

    CHECK(dns_cache_observe(cache, &packet, LOCAL_IP, 102) == 0);
    CHECK(dns_cache_lookup(cache, ip_addr_v4(REMOTE_IP), 131) == NULL);

    dns_cache_destroy(cache);
    store_close(store);
}

static void test_late_name_on_clean_eviction(void) {
    struct store *store = open_memory();
    struct dns_cache *cache = dns_cache_create(store, 8, 100);
    struct flow *flow = flow_create(LOCAL_IP, 1, 1);
    struct packet_view packet = service_packet();
    const struct dns_answer answer = answer_for(REMOTE_IP, "late.test", 60);
    struct store_row row;

    const struct flow_key key = {
        .us_ip = ip_addr_v4(LOCAL_IP), .remote_ip = ip_addr_v4(REMOTE_IP),
        .remote_port = 443, .protocol = IP_PROTO_TCP
    };

    CHECK(cache != NULL && flow != NULL);

    flow_set_store(flow, store);
    flow_set_dns_cache(flow, cache);

    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_tick(flow, 100) == 0);
    CHECK(dns_cache_update(cache, &answer, 101) == 1);

    packet.transport.tcp.dst_port = 80;

    CHECK(flow_observe(flow, &packet, 101) == 1);
    CHECK(flow_find(flow, &key) == NULL);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(strcmp(row.remote_name, "late.test") == 0);
    CHECK(row.delta.packets_out == 1);
    CHECK(flow_flush(flow) == 0);

    flow_destroy(flow);
    dns_cache_destroy(cache);
    store_close(store);
}

static void test_migration_failure_rolls_back(void) {
    char path[] = "/tmp/pigeon-dns-migrate-fail-XXXXXX";
    const int fd = mkstemp(path);
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    char error[STORE_ERROR_LEN];

    CHECK(fd != -1);
    CHECK(close(fd) == 0);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, STORE_CONVERSATIONS_V2_SQL
                      "CREATE TABLE dns_cache(conflict INTEGER);PRAGMA user_version=1;",
                      NULL, NULL, NULL) == SQLITE_OK);
    CHECK(store_open(path, error) == NULL);
    CHECK(sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &statement, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);
    CHECK(sqlite3_column_int(statement, 0) == 1);
    CHECK(sqlite3_finalize(statement) == SQLITE_OK);
    CHECK(sqlite3_close(db) == SQLITE_OK);
    CHECK(unlink(path) == 0);
}

int main(void) {
    test_ttl_replacement_and_capacity();
    test_persistent_reload();
    test_flow_naming(1);
    test_flow_naming(0);
    test_failure_preserves_memory_and_migration();
    test_observe_filters_and_partial_reply();
    test_late_name_on_clean_eviction();
    test_migration_failure_rolls_back();

    dns_cache_destroy(NULL);
    puts("dns_cache: ok");

    return 0;
}
