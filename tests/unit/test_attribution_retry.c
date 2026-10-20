#include <errno.h>
#include <string.h>
#include <pcap/pcap.h>

#include "../t.h"
#include "flow/flow.h"
#include "store/store.h"
#include "dns/dns_cache.h"

struct owner_state {
    int ready;
    uint16_t port;
};

static void resolve(const struct flow_key *key, uint16_t local_port, char out[FLOW_APP_LEN], void *user) {
    const struct owner_state *state = user;

    (void)key;
    out[0] = '\0';

    if (state->ready && local_port == state->port) {
        strcpy(out, "brave");
    }
}

static struct packet_view packet(int protocol, uint16_t local_port, int incoming, size_t bytes) {
    struct packet_view result = { .kind = protocol == 6 ? PACKET_TCP : PACKET_UDP };

    result.ip.src = incoming ? 0xc633642a : 0xc000020a;
    result.ip.dst = incoming ? 0xc000020a : 0xc633642a;
    result.ip.protocol = (uint8_t)protocol;

    if (protocol == 6) {
        result.transport.tcp.src_port = incoming ? 443 : local_port;
        result.transport.tcp.dst_port = incoming ? local_port : 443;
        result.transport.tcp.payload_wire_len = bytes;
    } else {
        result.transport.udp.src_port = incoming ? 443 : local_port;
        result.transport.udp.dst_port = incoming ? local_port : 443;
        result.transport.udp.payload_wire_len = bytes;
    }

    return result;
}

static struct flow_key key(int protocol, const char *application) {
    struct flow_key result = { .us_ip = ip_addr_v4(0xc000020a), .remote_ip = ip_addr_v4(0xc633642a),
                               .remote_port = 443, .protocol = (uint8_t)protocol };

    strcpy(result.application, application);

    return result;
}

static struct store *open_store(void) {
    char error[STORE_ERROR_LEN];
    struct store *store = store_open(":memory:", error);

    CHECK(store != NULL);

    return store;
}

static void test_late_owner(int protocol, int on_packet) {
    struct flow *flow = flow_create(0xc000020a, 16, 100);
    struct store *store = open_store();
    struct owner_state owner = { .port = 50000 };
    struct packet_view outgoing = packet(protocol, 50000, 0, 10);
    struct packet_view incoming = packet(protocol, 50000, 1, 20);
    struct flow_key known = key(protocol, "brave");
    struct flow_key unknown = key(protocol, "");
    struct store_row row;

    CHECK(flow != NULL);
    flow_set_store(flow, store);
    flow_set_application_resolver(flow, resolve, &owner);
    CHECK(flow_observe(flow, &outgoing, 100) == 1);
    CHECK(flow_observe(flow, &incoming, 101) == 1);
    CHECK(flow_pending_count(flow) == 1 && flow_count(flow) == 0);
    CHECK(flow_tick(flow, 101) == 0);
    CHECK(flow_pending_count(flow) == 1);
    CHECK(store_lookup(store, &unknown, &row) == 0);
    owner.ready = 1;

    if (on_packet) {
        CHECK(flow_observe(flow, &outgoing, 102) == 1);
    }

    CHECK(flow_tick(flow, 102) == 0);
    CHECK(flow_pending_count(flow) == 0 && flow_count(flow) == 1);
    CHECK(store_lookup(store, &known, &row) == 1);
    CHECK(row.delta.bytes_out == (on_packet ? 20 : 10) && row.delta.bytes_in == 20);
    CHECK(row.delta.packets_out == (on_packet ? 2 : 1) && row.delta.packets_in == 1);
    CHECK(row.delta.first_seen == 100 && row.delta.last_seen == (on_packet ? 102 : 101));
    CHECK(store_lookup(store, &unknown, &row) == 0);
    CHECK(flow_flush(flow) == 0 && flow_flush(flow) == 0);
    CHECK(store_lookup(store, &known, &row) == 1 && row.delta.bytes_in == 20);
    flow_destroy(flow);
    store_close(store);
}

static void test_timeout_and_ports(void) {
    struct flow *flow = flow_create(0xc000020a, 16, 100);
    struct store *store = open_store();
    struct owner_state owner = { .port = 50000 };
    struct packet_view first = packet(17, 50000, 0, 10);
    struct packet_view second = packet(17, 50001, 0, 20);
    struct flow_key known = key(17, "brave");
    struct flow_key unknown = key(17, "");
    struct store_row row;

    CHECK(flow != NULL);
    flow_set_store(flow, store);
    flow_set_application_resolver(flow, resolve, &owner);
    CHECK(flow_observe(flow, &first, 100) == 1);
    CHECK(flow_observe(flow, &second, 100) == 1);
    CHECK(flow_pending_count(flow) == 2);
    CHECK(flow_observe(flow, &second, 102) == 1);
    owner.ready = 1;
    CHECK(flow_tick(flow, 102) == 0);
    CHECK(flow_pending_count(flow) == 1);
    CHECK(store_lookup(store, &known, &row) == 1 && row.delta.bytes_out == 10);
    CHECK(flow_tick(flow, 103) == 0);
    CHECK(flow_pending_count(flow) == 0);
    CHECK(store_lookup(store, &unknown, &row) == 1 && row.delta.bytes_out == 40);
    CHECK(row.delta.first_seen == 100 && row.delta.last_seen == 102);

    /* Later ownership only affects new accounting, never historical rows. */
    owner.port = 50001;
    CHECK(flow_observe(flow, &second, 104) == 1 && flow_flush(flow) == 0);
    CHECK(store_lookup(store, &unknown, &row) == 1 && row.delta.bytes_out == 40);
    CHECK(store_lookup(store, &known, &row) == 1 && row.delta.bytes_out == 30);
    flow_destroy(flow);
    store_close(store);
}

static void test_capacity_and_shutdown(void) {
    struct flow *flow = flow_create(0xc000020a, 16, 100);
    struct store *store = open_store();
    struct owner_state owner = { 0 };
    struct flow_key unknown = key(6, "");
    struct store_row row;

    CHECK(flow != NULL);
    flow_set_store(flow, store);
    flow_set_application_resolver(flow, resolve, &owner);

    for (unsigned port = 10000; port < 11025; port++) {
        const struct packet_view value = packet(6, (uint16_t)port, 0, 7);

        CHECK(flow_observe(flow, &value, 100) == 1);
    }

    CHECK(flow_pending_count(flow) == 1024 && flow_count(flow) == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(flow_pending_count(flow) == 0);
    CHECK(store_lookup(store, &unknown, &row) == 1);
    CHECK(row.delta.packets_out == 1025 && row.delta.bytes_out == 1025 * 7);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &unknown, &row) == 1 && row.delta.packets_out == 1025);
    flow_destroy(flow);
    store_close(store);
}

static void test_failed_handoff(void) {
    struct flow *flow = flow_create(0xc000020a, 1, 1);
    struct owner_state owner = { .port = 50000, .ready = 1 };
    struct packet_view first = packet(6, 50000, 0, 10);
    struct packet_view second = packet(6, 50001, 0, 20);
    struct store *store = open_store();
    struct flow_key known = key(6, "brave");
    struct flow_key unknown = key(6, "");
    struct store_row row;

    CHECK(flow != NULL);
    flow_set_application_resolver(flow, resolve, &owner);
    CHECK(flow_observe(flow, &first, 100) == 1);
    CHECK(flow_observe(flow, &second, 100) == 1);
    CHECK(flow_tick(flow, 103) == -1 && errno == ENOSPC);
    CHECK(flow_pending_count(flow) == 1 && flow_count(flow) == 1);
    flow_set_store(flow, store);
    CHECK(flow_tick(flow, 104) == 0 && flow_pending_count(flow) == 0);
    CHECK(store_lookup(store, &known, &row) == 1 && row.delta.bytes_out == 10);
    CHECK(store_lookup(store, &unknown, &row) == 1 && row.delta.bytes_out == 20);
    flow_destroy(flow);
    store_close(store);
}

static void test_quic_retry(int ipv6, int resolved_on_packet) {
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *capture = pcap_open_offline(PIGEON_FIXTURE_DIR "/quic_conversations.pcap", error);
    struct ip_addr local;
    struct owner_state owner = { .port = 49152 };
    struct store *store = open_store();
    struct flow_key known = { .remote_port = ipv6 ? 443 : 8443, .protocol = 17 };
    struct store_row row;

    CHECK(capture != NULL);
    CHECK(ip_addr_parse(ipv6 ? "2001:db8::10" : "192.0.2.10", &local) == 0);
    CHECK(ip_addr_parse(ipv6 ? "2001:db8::42" : "198.51.100.42", &known.remote_ip) == 0);
    known.us_ip = local;
    strcpy(known.application, "brave");

    struct flow *flow = flow_create_addresses(&local, 1, 16, 100);

    CHECK(flow != NULL);
    flow_set_store(flow, store);
    flow_set_application_resolver(flow, resolve, &owner);

    int processed = 0;
    struct pcap_pkthdr *header;
    const u_char *data;

    while (pcap_next_ex(capture, &header, &data) == 1 && processed < 3) {
        struct packet_view value;

        CHECK(packet_parse(data, header->caplen, &value) == 0);

        if (packet_source(&value).family != local.family) {
            continue;
        }

        CHECK(flow_observe(flow, &value, 100 + processed) == 1);
        processed++;

        if (processed == 1 && resolved_on_packet) {
            owner.ready = 1;
        }
    }

    CHECK(processed == 3);
    owner.ready = 1;
    CHECK(flow_tick(flow, 102) == 0);
    CHECK(flow_pending_count(flow) == 0);
    CHECK(store_lookup(store, &known, &row) == 1 && row.quic);
    CHECK(row.delta.bytes_out == 1250 && row.delta.bytes_in == 80);
    CHECK(row.delta.packets_out == 2 && row.delta.packets_in == 1);
    CHECK(row.delta.first_seen == 100 && row.delta.last_seen == 102);
    flow_destroy(flow);
    store_close(store);
    pcap_close(capture);
}

static void test_overdue_retry(void) {
    struct owner_state owner = { .port = 50000 };
    struct flow *flow = flow_create(0xc000020a, 16, 100);
    struct store *store = open_store();
    struct packet_view value = packet(6, 50000, 0, 10);
    struct flow_key known = key(6, "brave");
    struct flow_key unknown = key(6, "");
    struct store_row row;

    CHECK(flow != NULL);
    flow_set_store(flow, store);
    flow_set_application_resolver(flow, resolve, &owner);
    CHECK(flow_observe(flow, &value, 100) == 1);
    owner.ready = 1;
    CHECK(flow_observe(flow, &value, 110) == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &unknown, &row) == 1 && row.delta.bytes_out == 10);
    CHECK(store_lookup(store, &known, &row) == 1 && row.delta.bytes_out == 10);
    flow_destroy(flow);
    store_close(store);
}

static void test_name_during_retry(void) {
    struct flow *flow = flow_create(0xc000020a, 16, 100);
    struct store *store = open_store();
    struct owner_state owner = { .port = 50000 };
    struct dns_cache *dns = dns_cache_create(store, 16, 100);
    struct dns_answer answer = { .ip = ip_addr_v4(0xc633642a), .ttl = 1, .name = "before.test" };
    struct packet_view value = packet(6, 50000, 0, 10);
    struct flow_key known = key(6, "brave");
    struct store_row row;

    CHECK(flow != NULL && dns != NULL);
    CHECK(dns_cache_update(dns, &answer, 100) == 1);
    flow_set_store(flow, store);
    flow_set_dns_cache(flow, dns);
    flow_set_application_resolver(flow, resolve, &owner);
    CHECK(flow_observe(flow, &value, 100) == 1);
    dns_cache_expire(dns, 102);
    owner.ready = 1;
    CHECK(flow_tick(flow, 102) == 0);
    CHECK(store_lookup(store, &known, &row) == 1);
    CHECK(strcmp(row.remote_name, "before.test") == 0);
    flow_destroy(flow);
    dns_cache_destroy(dns);
    store_close(store);
}

int main(void) {
    test_late_owner(6, 0);
    test_late_owner(6, 1);
    test_late_owner(17, 0);
    test_late_owner(17, 1);
    test_timeout_and_ports();
    test_capacity_and_shutdown();
    test_failed_handoff();
    test_name_during_retry();
    test_overdue_retry();
    test_quic_retry(0, 0);
    test_quic_retry(0, 1);
    test_quic_retry(1, 0);
    test_quic_retry(1, 1);

    return 0;
}
