#include <stdlib.h>
#include <string.h>

#include "../t.h"
#include "app/app_internal.h"
#include "flow/flow.h"
#include "store/store.h"

static struct app_socket socket_row(const char *local, const char *remote, uint16_t local_port,
                                     uint16_t remote_port, uint8_t protocol, const char *application) {
    struct app_socket row = { .local_port = local_port, .remote_port = remote_port,
                              .protocol = protocol, .owner_seen = application[0] != '\0' };

    CHECK(ip_addr_parse(local, &row.local) == 0);
    CHECK(ip_addr_parse(remote, &row.remote) == 0);
    strcpy(row.application, application);

    return row;
}

static void test_socket_matching(void) {
    struct app_socket rows[] = {
        socket_row("0.0.0.0", "0.0.0.0", 50000, 0, 17, "firefox"),
        socket_row("192.0.2.10", "198.51.100.42", 50000, 443, 17, "chromium"),
        socket_row("192.0.2.10", "198.51.100.42", 50000, 443, 6, "curl"),
        socket_row("2001:db8::10", "2001:db8::42", 50001, 443, 6, "firefox"),
        socket_row("::", "::", 50002, 0, 17, "firefox")
    };
    struct app_snapshot snapshot = { .sockets = rows, .count = sizeof rows / sizeof rows[0] };
    struct flow_key key = { .remote_port = 443, .protocol = 17 };
    char application[FLOW_APP_LEN];

    app_snapshot_sort(&snapshot);
    CHECK(ip_addr_parse("192.0.2.10", &key.us_ip) == 0);
    CHECK(ip_addr_parse("198.51.100.42", &key.remote_ip) == 0);
    app_snapshot_lookup(&snapshot, &key, 50000, application);
    CHECK(strcmp(application, "chromium") == 0);

    key.remote_port = 53;
    app_snapshot_lookup(&snapshot, &key, 50000, application);
    CHECK(strcmp(application, "firefox") == 0);
    app_snapshot_lookup(&snapshot, &key, 50002, application);
    CHECK(application[0] == '\0');

    key.protocol = 6;
    key.remote_port = 443;
    app_snapshot_lookup(&snapshot, &key, 50000, application);
    CHECK(strcmp(application, "curl") == 0);

    CHECK(ip_addr_parse("2001:db8::10", &key.us_ip) == 0);
    CHECK(ip_addr_parse("2001:db8::42", &key.remote_ip) == 0);
    app_snapshot_lookup(&snapshot, &key, 50001, application);
    CHECK(strcmp(application, "firefox") == 0);

    key.protocol = 17;
    app_snapshot_lookup(&snapshot, &key, 50002, application);
    CHECK(strcmp(application, "firefox") == 0);

    struct app_socket shared[] = {
        socket_row("0.0.0.0", "0.0.0.0", 12345, 0, 17, "firefox"),
        socket_row("0.0.0.0", "0.0.0.0", 12345, 0, 17, "chromium")
    };

    snapshot.sockets = shared;
    snapshot.count = 2;
    CHECK(ip_addr_parse("192.0.2.10", &key.us_ip) == 0);
    CHECK(ip_addr_parse("198.51.100.42", &key.remote_ip) == 0);
    app_snapshot_lookup(&snapshot, &key, 12345, application);
    CHECK(application[0] == '\0');

    strcpy(shared[1].application, "firefox");
    app_snapshot_lookup(&snapshot, &key, 12345, application);
    CHECK(strcmp(application, "firefox") == 0);

    shared[1].owner_seen = 0;
    app_snapshot_lookup(&snapshot, &key, 12345, application);
    CHECK(application[0] == '\0');

    shared[1].owner_seen = 1;
    shared[1].ambiguous = 1;
    app_snapshot_lookup(&snapshot, &key, 12345, application);
    CHECK(application[0] == '\0');

    app_snapshot_lookup(NULL, &key, 12345, application);
    CHECK(application[0] == '\0');
}

static void resolve(const struct flow_key *key, uint16_t port, char out[FLOW_APP_LEN], void *user) {
    (void)user;

    CHECK(key->remote_port == 443);
    strcpy(out, port == 50000 || port == 50001 ? "firefox" : "chromium");
}

static void test_application_grouping(void) {
    char error[STORE_ERROR_LEN];
    struct store *store = store_open(":memory:", error);
    struct flow *flow = flow_create(0xc000020a, 1, 8);
    struct packet_view packet = { .kind = PACKET_TCP,
        .ip = { .src = 0xc000020a, .dst = 0xc633642a, .protocol = 6 },
        .transport.tcp = { .src_port = 50000, .dst_port = 443, .payload_wire_len = 10 } };
    struct flow_key key = { .us_ip = ip_addr_v4(0xc000020a), .remote_ip = ip_addr_v4(0xc633642a),
                            .remote_port = 443, .protocol = 6 };
    struct store_row row;

    CHECK(store != NULL && flow != NULL);
    flow_set_store(flow, store);
    flow_set_application_resolver(flow, resolve, NULL);
    CHECK(flow_observe(flow, &packet, 100) == 1);

    packet.transport.tcp.src_port = 50001;
    CHECK(flow_observe(flow, &packet, 101) == 1);

    packet.ip.src = 0xc633642a;
    packet.ip.dst = 0xc000020a;
    packet.transport.tcp.src_port = 443;
    packet.transport.tcp.dst_port = 50001;
    CHECK(flow_observe(flow, &packet, 102) == 1);

    packet.transport.tcp.dst_port = 50002;
    CHECK(flow_observe(flow, &packet, 103) == 1);
    CHECK(flow_count(flow) == 2);

    flow_set_application_resolver(flow, NULL, NULL);
    CHECK(flow_observe(flow, &packet, 104) == 1);
    CHECK(flow_count(flow) == 3);
    CHECK(flow_flush(flow) == 0);

    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.bytes_in == 10);

    strcpy(key.application, "firefox");
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.bytes_out == 20 && row.delta.bytes_in == 10);
    CHECK(row.delta.packets_out == 2 && row.delta.packets_in == 1);

    strcpy(key.application, "chromium");
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.bytes_out == 0 && row.delta.bytes_in == 10);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.bytes_in == 10);

    flow_destroy(flow);
    store_close(store);
}

int main(void) {
    test_socket_matching();
    test_application_grouping();

    return 0;
}
