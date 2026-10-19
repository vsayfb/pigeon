#include <string.h>

#include "../t.h"
#include "proto/packet.h"
#include "flow/flow.h"
#include "store/store.h"

static size_t frame(uint8_t *data, int ipv6, int incoming, uint8_t type, uint8_t code) {
    memset(data, 0, 128);
    data[12] = ipv6 ? 0x86 : 0x08;
    data[13] = ipv6 ? 0xdd : 0;

    const size_t header = ipv6 ? 40 : 20;
    uint8_t *ip = data + 14;
    struct ip_addr local;
    struct ip_addr remote;

    CHECK(ip_addr_parse(ipv6 ? "2001:db8::10" : "192.0.2.10", &local) == 0);
    CHECK(ip_addr_parse(ipv6 ? "2001:db8::42" : "198.51.100.42", &remote) == 0);

    ip[0] = ipv6 ? 0x60 : 0x45;

    if (ipv6) {
        ip[5] = 12;
        ip[6] = IP_PROTO_ICMPV6;
        memcpy(ip + 8, incoming ? remote.bytes : local.bytes, 16);
        memcpy(ip + 24, incoming ? local.bytes : remote.bytes, 16);
    } else {
        ip[3] = 32;
        ip[9] = IP_PROTO_ICMP;
        memcpy(ip + 12, incoming ? remote.bytes : local.bytes, 4);
        memcpy(ip + 16, incoming ? local.bytes : remote.bytes, 4);
    }

    uint8_t *icmp = ip + header;

    icmp[0] = type;
    icmp[1] = code;
    memcpy(icmp + 8, "ping", 4);

    return 14 + header + 12;
}

static void no_application(const struct flow_key *key, uint16_t port,
                            char out[FLOW_APP_LEN], void *user) {
    (void)key;
    (void)port;
    (void)out;
    (void)user;

    CHECK(0); /* ICMP must never be resolved through TCP/UDP socket ports. */
}

static void test_family(int ipv6) {
    uint8_t data[128];
    struct packet_view packet;
    const size_t len = frame(data, ipv6, 0, ipv6 ? 128 : 8, 0);
    const size_t header_end = len - 4;

    CHECK(packet_parse(data, len + 10, &packet) == 0); /* Ethernet padding */
    CHECK(packet.kind == (ipv6 ? PACKET_ICMPV6 : PACKET_ICMP));
    CHECK(packet.transport.icmp.type == (ipv6 ? 128 : 8));
    CHECK(packet.transport.icmp.code == 0);
    CHECK(packet.transport.icmp.payload_len == 4);
    CHECK(packet.transport.icmp.payload_wire_len == 4);
    CHECK(memcmp(packet.transport.icmp.payload, "ping", 4) == 0);

    for (size_t cut = 14 + (ipv6 ? 40 : 20); cut < header_end; cut++) {
        struct packet_view before;

        memset(&packet, 0xa5, sizeof packet);
        memcpy(&before, &packet, sizeof packet);

        CHECK(packet_parse(data, cut, &packet) == -1);
        CHECK(memcmp(&packet, &before, sizeof packet) == 0);
    }

    /* Type-specific echo/error bytes must also fit the declared wire length. */
    struct icmp_view message = { 0 };
    struct icmp_view before = message;

    CHECK(icmp_parse(data + header_end - 8, 12, 7, ipv6, &message) == -1);
    CHECK(memcmp(&message, &before, sizeof message) == 0);
    CHECK(packet_parse(data, header_end + 1, &packet) == 0);
    CHECK(packet.transport.icmp.payload_len == 1);
    CHECK(packet.transport.icmp.payload_wire_len == 4);

    struct ip_addr local;
    struct flow_key key = { .protocol = ipv6 ? IP_PROTO_ICMPV6 : IP_PROTO_ICMP };

    CHECK(ip_addr_parse(ipv6 ? "2001:db8::10" : "192.0.2.10", &local) == 0);
    key.us_ip = local;
    CHECK(ip_addr_parse(ipv6 ? "2001:db8::42" : "198.51.100.42", &key.remote_ip) == 0);

    struct flow *flow = flow_create_addresses(&local, 1, 16, 8);
    char error[STORE_ERROR_LEN];
    struct store *store = store_open(":memory:", error);
    struct store_row row;

    CHECK(flow != NULL && store != NULL);
    flow_set_store(flow, store);
    flow_set_application_resolver(flow, no_application, NULL);
    CHECK(flow_observe(flow, &packet, 100) == 1);
    frame(data, ipv6, 1, ipv6 ? 129 : 0, 0);
    CHECK(packet_parse(data, len, &packet) == 0);
    CHECK(flow_observe(flow, &packet, 101) == 1);
    CHECK(flow_count(flow) == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 1 && row.delta.packets_in == 1);
    CHECK(row.delta.bytes_out == 4 && row.delta.bytes_in == 4);
    CHECK(row.key.remote_port == 0 && row.key.application[0] == '\0');

    /* Error messages count the outer sender; quoted packets are not recursed
     * into and cannot impersonate a TCP/UDP application conversation. */
    frame(data, ipv6, 1, ipv6 ? 1 : 3, 1);
    CHECK(packet_parse(data, len, &packet) == 0);
    CHECK(packet.transport.icmp.code == 1);
    CHECK(flow_observe(flow, &packet, 102) == 1);
    CHECK(flow_count(flow) == 1);

    if (ipv6) {
        const uint8_t local_types[] = {130, 131, 132, 133, 134, 135, 136, 137, 143};

        for (size_t i = 0; i < sizeof local_types; i++) {
            frame(data, 1, 1, local_types[i], 0);
            CHECK(packet_parse(data, len, &packet) == 0);
            CHECK(flow_observe(flow, &packet, 103) == 0);
        }
    } else {
        data[20] = 0;
        data[21] = 1; /* IPv4 fragment offset, after Ethernet */
        CHECK(packet_parse(data, len, &packet) == 0);
        CHECK(packet.kind == PACKET_IPV4);
        CHECK(flow_observe(flow, &packet, 103) == 0);
    }

    CHECK(flow_tick(flow, 132) == 0);
    CHECK(flow_count(flow) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_in == 2);

    flow_destroy(flow);
    store_close(store);
}

int main(void) {
    test_family(0);
    test_family(1);
    puts("icmp: ok");

    return 0;
}
