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

static void test_owner_cache(void) {
    struct app_socket original = socket_row("192.0.2.10", "198.51.100.42", 50000, 443, 17, "brave");
    struct app_socket missing = socket_row("192.0.2.10", "198.51.100.42", 50000, 443, 17, "");
    struct app_snapshot previous = { .sockets = &original, .count = 1, .sampled_at = 100 };
    struct app_snapshot next = { .sockets = &missing, .count = 1, .sampled_at = 101 };
    struct flow_key key = { .us_ip = ip_addr_v4(0xc000020a), .remote_ip = ip_addr_v4(0xc633642a),
                            .remote_port = 443, .protocol = 17 };
    char application[FLOW_APP_LEN];

    original.inode = missing.inode = 42;
    original.cookie = missing.cookie = 99;
    original.cookie_valid = missing.cookie_valid = 1;
    app_snapshot_cache_owners(&previous, NULL, 100);
    app_snapshot_cache_owners(&next, &previous, 101);
    app_snapshot_lookup_at(&next, &key, 50000, 101, application);
    CHECK(strcmp(application, "brave") == 0);
    CHECK(missing.owner_cached && missing.owner_confirmed_at == 100);
    app_snapshot_lookup_at(&next, &key, 50001, 101, application);
    CHECK(application[0] == '\0');
    app_snapshot_lookup_at(&next, &key, 50000, 105, application);
    CHECK(application[0] == '\0');

    /* Cached hits must not renew their own evidence lifetime. */
    struct app_socket again = missing;
    struct app_snapshot later = { .sockets = &again, .count = 1 };

    again.owner_seen = again.owner_cached = 0;
    again.application[0] = '\0';
    app_snapshot_cache_owners(&later, &next, 104);
    CHECK(again.owner_cached && again.owner_confirmed_at == 100);
    again.owner_seen = again.owner_cached = 0;
    again.application[0] = '\0';
    app_snapshot_cache_owners(&later, &next, 105);
    CHECK(!again.owner_seen);

    /* Same port/peer does not authorize reuse by a different kernel socket,
     * another tuple, or a conflicting/ambiguous owner. */
    for (int scenario = 0; scenario < 8; scenario++) {
        again = original;
        again.owner_seen = again.owner_cached = 0;
        again.application[0] = '\0';

        switch (scenario) {
            case 0: again.cookie++; break;
            case 1: again.inode++; break;
            case 2: again.local_port++; break;
            case 3: again.protocol = 6; break;
            case 4: again.remote_port++; break;
            case 5: again.ambiguous = 1; break;
            case 6: again.cookie_valid = 0; break;
            case 7: again.remote = ip_addr_v4(0xc633642b); break;
        }

        app_snapshot_cache_owners(&later, &previous, 101);
        CHECK(!again.owner_seen);
    }

    /* Positive new evidence wins over cached ownership immediately. */
    again = original;
    strcpy(again.application, "firefox");
    app_snapshot_cache_owners(&later, &previous, 101);
    CHECK(strcmp(again.application, "firefox") == 0 && !again.owner_cached);
    CHECK(again.owner_confirmed_at == 101);

    /* A socket absent from the new snapshot is never revived from cache. */
    later.count = 0;
    app_snapshot_cache_owners(&later, &previous, 101);
    app_snapshot_lookup_at(&later, &key, 50000, 101, application);
    CHECK(application[0] == '\0');
}

static void test_diagnostic_reasons(void) {
    struct app_socket rows[] = {
        socket_row("192.0.2.10", "198.51.100.42", 50000, 443, 6, "brave"),
        socket_row("192.0.2.10", "198.51.100.42", 50001, 443, 6, ""),
        socket_row("192.0.2.10", "198.51.100.42", 50002, 443, 6, "brave"),
        socket_row("192.0.2.10", "198.51.100.42", 50002, 443, 6, "firefox"),
        socket_row("192.0.2.10", "198.51.100.42", 50003, 443, 6, "brave")
    };
    struct app_snapshot snapshot = { .sockets = rows, .count = 5 };
    struct flow_key key = { .us_ip = ip_addr_v4(0xc000020a), .remote_ip = ip_addr_v4(0xc633642a),
                            .remote_port = 443, .protocol = 6 };
    char application[FLOW_APP_LEN];

    rows[4].owner_cached = 1;
    rows[4].owner_confirmed_at = 100;
    app_snapshot_sort(&snapshot);
    CHECK(app_snapshot_diagnose(NULL, &key, 50000, 101, application) == APP_LOOKUP_NO_SNAPSHOT);
    CHECK(app_snapshot_diagnose(&snapshot, &key, 50000, 101, application) == APP_LOOKUP_SNAPSHOT);
    CHECK(strcmp(application, "brave") == 0);
    CHECK(app_snapshot_diagnose(&snapshot, &key, 49999, 101, application) == APP_LOOKUP_NO_SOCKET);
    CHECK(application[0] == '\0');
    CHECK(app_snapshot_diagnose(&snapshot, &key, 50001, 101, application) == APP_LOOKUP_OWNER_MISSING);
    CHECK(app_snapshot_diagnose(&snapshot, &key, 50002, 101, application) == APP_LOOKUP_AMBIGUOUS);
    CHECK(application[0] == '\0');
    CHECK(app_snapshot_diagnose(&snapshot, &key, 50003, 101, application) == APP_LOOKUP_CACHE);
    CHECK(app_snapshot_diagnose(&snapshot, &key, 50003, 105, application) == APP_LOOKUP_CACHE_EXPIRED);
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
    test_owner_cache();
    test_diagnostic_reasons();

    return 0;
}
