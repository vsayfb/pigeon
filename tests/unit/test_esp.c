#include <string.h>

#include "../t.h"
#include "proto/packet.h"
#include "flow/flow.h"
#include "store/store.h"

static size_t frame(uint8_t *data, int ipv6, int incoming, int natt) {
    memset(data, 0, 128);
    data[12] = ipv6 ? 0x86 : 0x08;
    data[13] = ipv6 ? 0xdd : 0;

    uint8_t *ip = data + 14;
    const size_t ip_len = ipv6 ? 40 : 20;
    const size_t payload = 16 + (natt ? 8 : 0);
    struct ip_addr local;
    struct ip_addr remote;

    CHECK(ip_addr_parse(ipv6 ? "2001:db8::10" : "192.0.2.10", &local) == 0);
    CHECK(ip_addr_parse(ipv6 ? "2001:db8::42" : "198.51.100.42", &remote) == 0);
    ip[0] = ipv6 ? 0x60 : 0x45;

    if (ipv6) {
        ip[5] = (uint8_t)payload;
        ip[6] = natt ? IP_PROTO_UDP : IP_PROTO_ESP;
        memcpy(ip + 8, incoming ? remote.bytes : local.bytes, 16);
        memcpy(ip + 24, incoming ? local.bytes : remote.bytes, 16);
    } else {
        ip[3] = (uint8_t)(ip_len + payload);
        ip[9] = natt ? IP_PROTO_UDP : IP_PROTO_ESP;
        memcpy(ip + 12, incoming ? remote.bytes : local.bytes, 4);
        memcpy(ip + 16, incoming ? local.bytes : remote.bytes, 4);
    }

    uint8_t *esp = ip + ip_len;

    if (natt) {
        esp[0] = incoming ? 0x11 : 0xea;
        esp[1] = incoming ? 0x94 : 0x60;
        esp[2] = incoming ? 0xea : 0x11;
        esp[3] = incoming ? 0x60 : 0x94;
        esp[5] = (uint8_t)payload;
        esp += 8;
    }

    esp[3] = incoming ? 2 : 1; /* Different directional SPIs still form one peer aggregate. */
    esp[7] = 7;
    memcpy(esp + 8, "opaque!!", 8);

    return 14 + ip_len + payload;
}

static void no_owner(const struct flow_key *key, uint16_t port,
                      char out[FLOW_APP_LEN], void *user) {
    (void)key;
    (void)port;
    (void)out;
    (void)user;
    CHECK(0); /* ESP's inner socket owner cannot be inferred from its envelope. */
}

static void family(int ipv6) {
    uint8_t data[128];
    struct packet_view packet;
    struct ip_addr local;
    struct flow_key key = { .protocol = IP_PROTO_ESP };
    char error[STORE_ERROR_LEN];

    CHECK(ip_addr_parse(ipv6 ? "2001:db8::10" : "192.0.2.10", &local) == 0);
    key.us_ip = local;
    CHECK(ip_addr_parse(ipv6 ? "2001:db8::42" : "198.51.100.42", &key.remote_ip) == 0);

    struct flow *flow = flow_create_addresses(&local, 1, 16, 8);
    struct store *store = store_open(":memory:", error);
    struct store_row row;

    CHECK(flow != NULL && store != NULL);
    flow_set_store(flow, store);
    flow_set_application_resolver(flow, no_owner, NULL);

    for (int natt = 0; natt <= 1; natt++) {
        for (int incoming = 0; incoming <= 1; incoming++) {
            const size_t len = frame(data, ipv6, incoming, natt);

            CHECK(packet_parse(data, len + 8, &packet) == 0); /* Ignore Ethernet padding. */
            CHECK(packet.kind == PACKET_ESP);
            CHECK(packet.esp.udp_encapsulated == natt);
            CHECK(packet_protocol(&packet) == (natt ? IP_PROTO_UDP : IP_PROTO_ESP));
            CHECK(packet.esp.spi == (incoming ? 2u : 1u) && packet.esp.sequence == 7);
            CHECK(packet.esp.payload_len == 8 && packet.esp.payload_wire_len == 8);
            CHECK(flow_observe(flow, &packet, 100 + natt + incoming) == 1);
        }
    }

    CHECK(flow_count(flow) == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 2 && row.delta.packets_in == 2);
    CHECK(row.delta.bytes_out == 16 && row.delta.bytes_in == 16);
    CHECK(row.key.application[0] == '\0' && row.key.remote_port == 0 && row.quic == 0);

    const size_t len = frame(data, ipv6, 0, 0);
    const size_t header_end = len - 8;

    CHECK(packet_parse(data, header_end, &packet) == 0);
    CHECK(packet.esp.payload_len == 0 && packet.esp.payload_wire_len == 8);

    for (size_t cut = header_end - 8; cut < header_end; cut++) {
        struct packet_view before;

        memset(&packet, 0xa5, sizeof packet);
        memcpy(&before, &packet, sizeof packet);
        CHECK(packet_parse(data, cut, &packet) == -1);
        CHECK(memcmp(&before, &packet, sizeof packet) == 0);
    }

    data[header_end - 5] = 0; /* Reserved SPI zero is invalid for native ESP. */
    CHECK(packet_parse(data, len, &packet) == -1);
    frame(data, ipv6, 0, 1);
    memset(data + header_end, 0, 4); /* Non-ESP marker at the UDP payload. */
    CHECK(packet_parse(data, len + 8, &packet) == 0 && packet.kind == PACKET_UDP);

    CHECK(flow_tick(flow, 132) == 0);
    CHECK(flow_count(flow) == 0);
    flow_destroy(flow);
    store_close(store);
}

int main(void) {
    family(0);
    family(1);
    puts("esp: ok");

    return 0;
}
