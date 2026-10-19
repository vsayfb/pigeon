#include <errno.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <unistd.h>

#include "../t.h"
#include "flow/flow.h"
#include "store/store.h"

#define LOCAL_IP UINT32_C(0xC000020A)
#define REMOTE_IP UINT32_C(0xC6336414)

static struct flow_key key_for(uint16_t port, uint8_t protocol) {
    const struct flow_key key = {
        .us_ip = LOCAL_IP, .remote_ip = REMOTE_IP,
        .remote_port = port, .protocol = protocol
    };

    return key;
}

static void observe(struct flow *flow, uint16_t port, int udp, int64_t now) {
    struct packet_view packet = { 0 };

    packet.kind = udp ? PACKET_UDP : PACKET_TCP;
    packet.ip.src = LOCAL_IP;
    packet.ip.dst = REMOTE_IP;
    packet.ip.protocol = udp ? IP_PROTO_UDP : IP_PROTO_TCP;

    if (udp) {
        packet.transport.udp.src_port = 49152;
        packet.transport.udp.dst_port = port;
        packet.transport.udp.payload_wire_len = 5;
    } else {
        packet.transport.tcp.src_port = 49152;
        packet.transport.tcp.dst_port = port;
        packet.transport.tcp.payload_wire_len = 10;
    }

    CHECK(flow_observe(flow, &packet, now) == 1);
}

static struct store *open_memory(void) {
    char error[STORE_ERROR_LEN];
    struct store *store = store_open(":memory:", error);

    CHECK(store != NULL);

    return store;
}

static void test_throttle_and_shutdown_flush(void) {
    struct store *store = open_memory();
    struct flow *flow = flow_create(LOCAL_IP, 4, 8);
    const struct flow_key key = key_for(443, IP_PROTO_TCP);
    struct store_row row;

    CHECK(flow != NULL);

    flow_set_store(flow, store);
    observe(flow, 443, 0, 100);

    CHECK(flow_tick(flow, 100) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 1);
    CHECK(flow_entry_delta(flow_find(flow, &key))->packets_out == 0);

    observe(flow, 443, 0, 100);

    CHECK(flow_tick(flow, 100) == 0);
    CHECK(flow_tick(flow, 99) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 1);
    CHECK(flow_entry_delta(flow_find(flow, &key))->packets_out == 1);
    CHECK(flow_tick(flow, 101) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 2);
    CHECK(row.delta.bytes_out == 20);
    CHECK(row.delta.first_seen == 100);

    observe(flow, 443, 0, 101);

    /* Shutdown flush bypasses the same-second periodic throttle. */
    CHECK(flow_flush(flow) == 0);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 3);
    CHECK(row.delta.bytes_out == 30);
    CHECK(row.delta.last_seen == 101);

    flow_destroy(flow);
    store_close(store);
}

static void test_expiry_boundaries(void) {
    struct store *store = open_memory();
    struct flow *flow = flow_create(LOCAL_IP, 4, 8);
    const struct flow_key tcp = key_for(443, IP_PROTO_TCP);
    const struct flow_key udp = key_for(53, IP_PROTO_UDP);
    struct store_row row;

    CHECK(flow != NULL);

    flow_set_store(flow, store);
    observe(flow, 443, 0, 100);
    observe(flow, 53, 1, 100);

    CHECK(flow_tick(flow, 129) == 0);
    CHECK(flow_count(flow) == 2);
    CHECK(flow_tick(flow, 130) == 0);
    CHECK(flow_find(flow, &udp) == NULL);
    CHECK(flow_find(flow, &tcp) != NULL);
    CHECK(store_lookup(store, &udp, &row) == 1);
    CHECK(row.delta.bytes_out == 5);
    CHECK(flow_tick(flow, 219) == 0);
    CHECK(flow_count(flow) == 1);
    CHECK(flow_tick(flow, 220) == 0);
    CHECK(flow_count(flow) == 0);
    CHECK(store_lookup(store, &tcp, &row) == 1);
    CHECK(row.delta.bytes_out == 10);

    flow_destroy(flow);
    store_close(store);
}

static void test_eviction_flushes_dirty_only(void) {
    struct store *store = open_memory();
    struct flow *flow = flow_create(LOCAL_IP, 1, 1);
    const struct flow_key a = key_for(80, IP_PROTO_TCP);
    const struct flow_key b = key_for(443, IP_PROTO_TCP);
    struct store_row row;

    CHECK(flow != NULL);

    flow_set_store(flow, store);
    observe(flow, 80, 0, 100);
    observe(flow, 443, 0, 101);

    CHECK(flow_find(flow, &a) == NULL);
    CHECK(store_lookup(store, &a, &row) == 1);
    CHECK(row.delta.packets_out == 1);
    CHECK(flow_tick(flow, 101) == 0);

    observe(flow, 22, 0, 102);

    CHECK(flow_find(flow, &b) == NULL);
    CHECK(store_lookup(store, &b, &row) == 1);
    CHECK(row.delta.packets_out == 1);
    CHECK(flow_flush(flow) == 0);

    flow_destroy(flow);
    store_close(store);
}

static void test_failed_writes_preserve_entries_and_retry(void) {
    char path[] = "/tmp/pigeon-flow-flush-XXXXXX";
    const int fd = mkstemp(path);

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    char error[STORE_ERROR_LEN];
    struct store *store = store_open(path, error);
    struct flow *flow = flow_create(LOCAL_IP, 1, 2);
    sqlite3 *db = NULL;
    const struct flow_key a = key_for(80, IP_PROTO_TCP);
    const struct flow_key b = key_for(443, IP_PROTO_TCP);
    struct store_row row;

    CHECK(store != NULL);
    CHECK(flow != NULL);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TRIGGER reject_write BEFORE INSERT ON conversations "
                      "WHEN NEW.remote_port=80 BEGIN SELECT RAISE(ABORT,'test failure'); END",
                      NULL, NULL, NULL) == SQLITE_OK);

    flow_set_store(flow, store);
    observe(flow, 80, 0, 100);
    observe(flow, 443, 0, 100);

    CHECK(flow_tick(flow, 300) == -1);
    CHECK(errno == EIO);
    CHECK(flow_count(flow) == 2);
    CHECK(flow_entry_delta(flow_find(flow, &a))->packets_out == 1);
    CHECK(flow_entry_delta(flow_find(flow, &b))->packets_out == 1);
    CHECK(store_lookup(store, &b, &row) == 0);

    /* Failed periodic attempts are throttled; pending traffic remains. */
    CHECK(flow_tick(flow, 300) == 0);
    CHECK(flow_count(flow) == 2);

    struct packet_view packet = { 0 };

    packet.kind = PACKET_TCP;
    packet.ip.src = LOCAL_IP;
    packet.ip.dst = REMOTE_IP;
    packet.ip.protocol = IP_PROTO_TCP;
    packet.transport.tcp.dst_port = 22;

    CHECK(flow_observe(flow, &packet, 300) == -1);
    CHECK(flow_count(flow) == 2);
    CHECK(flow_find(flow, &a) != NULL);

    CHECK(sqlite3_exec(db, "DROP TRIGGER reject_write", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(flow_tick(flow, 301) == 0);
    CHECK(flow_count(flow) == 0);
    CHECK(store_lookup(store, &a, &row) == 1);
    CHECK(row.delta.packets_out == 1);
    CHECK(store_lookup(store, &b, &row) == 1);
    CHECK(row.delta.packets_out == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(sqlite3_close(db) == SQLITE_OK);

    flow_destroy(flow);
    store_close(store);

    CHECK(unlink(path) == 0);
}

int main(void) {
    test_throttle_and_shutdown_flush();
    test_expiry_boundaries();
    test_eviction_flushes_dirty_only();
    test_failed_writes_preserve_entries_and_retry();

    puts("flow_flush: ok");

    return 0;
}
