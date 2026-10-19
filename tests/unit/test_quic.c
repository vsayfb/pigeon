#include <string.h>

#include "../t.h"
#include "proto/quic.h"
#include "proto/packet.h"
#include "flow/flow.h"
#include "store/store.h"

static size_t packet(uint8_t *data, int v2, int initial, const char dcid[8], const char scid[8]) {
    const size_t size = initial ? 1200 : 80;
    const unsigned type = initial ? (v2 ? 1 : 0) : (v2 ? 3 : 2);
    const uint32_t version = v2 ? UINT32_C(0x6b3343cf) : 1;

    memset(data, 0, 1200);
    data[0] = (uint8_t)(0xc0 | (type << 4));

    for (unsigned i = 0; i < 4; i++) {
        data[1 + i] = (uint8_t)(version >> (24 - 8 * i));
    }

    data[5] = 8;
    memcpy(data + 6, dcid, 8);
    data[14] = 8;
    memcpy(data + 15, scid, 8);

    const size_t offset = initial ? 24 : 23;
    const size_t length = size - offset - 2;

    data[offset] = 0x40 | (uint8_t)(length >> 8);
    data[offset + 1] = (uint8_t)length;

    return size;
}

static void test_detection(int v2) {
    uint8_t data[1200];
    struct quic_header header;
    struct quic_probe probe = { 0 };
    size_t size = packet(data, v2, 1, "server00", "client00");

    CHECK(quic_parse_long(data, size, &header) == 1);
    CHECK(header.initial && header.scid_len == 8 && header.dcid_len == 8);

    for (size_t cut = 0; cut < size; cut++) {
        struct quic_header before;

        memset(&header, 0xa5, sizeof header);
        memcpy(&before, &header, sizeof header);
        CHECK(quic_parse_long(data, cut, &header) == 0);
        CHECK(memcmp(&before, &header, sizeof header) == 0);
    }

    CHECK(quic_observe(&probe, data, size, size, 49152, 1, 100) == 0);
    CHECK(probe.active);
    size = packet(data, v2, 0, "client00", "server01");
    CHECK(quic_observe(&probe, data, size, size, 49153, 0, 101) == 0);
    CHECK(quic_observe(&probe, data, size, size, 49152, 1, 101) == 0);
    CHECK(quic_observe(&probe, data, size, size, 49152, 0, 99) == 0);
    CHECK(quic_observe(&probe, data, size, size, 49152, 0, 131) == 0);
    data[6] ^= 1;
    CHECK(quic_observe(&probe, data, size, size, 49152, 0, 101) == 0);
    data[6] ^= 1;
    CHECK(quic_observe(&probe, data, size, size, 49152, 0, 101) == 1);

    /* Unsupported versions, Retry, malformed lengths and short headers. */
    data[1] ^= 1;
    CHECK(quic_parse_long(data, size, &header) == 0);
    data[1] ^= 1;
    data[0] = v2 ? 0xc0 : 0xf0;
    CHECK(quic_parse_long(data, size, &header) == 0);
    data[0] = 0x40;
    CHECK(quic_parse_long(data, size, &header) == 0);
    size = packet(data, v2, 1, "server00", "client00");
    data[5] = 21;
    CHECK(quic_parse_long(data, size, &header) == 0);
    packet(data, v2, 1, "server00", "client00");
    data[23] = 0xff; /* 8-byte token length, far outside the datagram. */
    CHECK(quic_parse_long(data, size, &header) == 0);
    packet(data, v2, 1, "server00", "client00");
    data[24] = 0;
    CHECK(quic_parse_long(data, size, &header) == 0);
}

static struct packet_view udp(int ipv6, int incoming, const uint8_t *data, size_t size) {
    struct packet_view view = { .kind = PACKET_UDP };
    struct ip_addr local;
    struct ip_addr remote;

    CHECK(ip_addr_parse(ipv6 ? "2001:db8::10" : "192.0.2.10", &local) == 0);
    CHECK(ip_addr_parse(ipv6 ? "2001:db8::42" : "198.51.100.42", &remote) == 0);
    view.eth.ethertype = ipv6 ? ETHERTYPE_IPV6 : ETHERTYPE_IPV4;

    if (ipv6) {
        view.ip6.src = incoming ? remote : local;
        view.ip6.dst = incoming ? local : remote;
        view.ip6.protocol = IP_PROTO_UDP;
    } else {
        view.ip.src = incoming ? 0xc633642a : 0xc000020a;
        view.ip.dst = incoming ? 0xc000020a : 0xc633642a;
        view.ip.protocol = IP_PROTO_UDP;
    }

    view.transport.udp = (struct udp_view){
        .src_port = incoming ? 8443 : 49152,
        .dst_port = incoming ? 49152 : 8443,
        .payload = data, .payload_len = size, .payload_wire_len = size
    };

    return view;
}

static void test_aggregate(int ipv6) {
    uint8_t data[1200];
    struct ip_addr local;
    struct flow_key key = { .remote_port = 8443, .protocol = 17 };
    char error[STORE_ERROR_LEN];
    struct store *store = store_open(":memory:", error);
    struct store_row row;

    CHECK(ip_addr_parse(ipv6 ? "2001:db8::10" : "192.0.2.10", &local) == 0);
    CHECK(ip_addr_parse(ipv6 ? "2001:db8::42" : "198.51.100.42", &key.remote_ip) == 0);
    key.us_ip = local;

    struct flow *flow = flow_create_addresses(&local, 1, 16, 8);
    size_t size = packet(data, ipv6, 1, "server00", "client00");
    struct packet_view view = udp(ipv6, 0, data, size);

    CHECK(flow != NULL && store != NULL);
    flow_set_store(flow, store);
    CHECK(flow_observe(flow, &view, 100) == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &key, &row) == 1 && row.quic == 0);

    const struct flow_entry *entry = flow_find(flow, &key);

    size = packet(data, ipv6, 0, "client00", "server01");
    view = udp(ipv6, 1, data, size);
    CHECK(flow_observe(flow, &view, 101) == 1);
    CHECK(flow_find(flow, &key) == entry && flow_count(flow) == 1);
    CHECK(flow_entry_quic(entry) == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &key, &row) == 1 && row.quic == 1);
    CHECK(row.delta.bytes_out == 1200 && row.delta.bytes_in == 80);
    CHECK(row.delta.packets_out == 1 && row.delta.packets_in == 1);
    CHECK(flow_tick(flow, 131) == 0);
    CHECK(flow_count(flow) == 0);

    /* A later short-only observation cannot erase persisted classification. */
    data[0] = 0x40;
    view = udp(ipv6, 0, data, 50);
    CHECK(flow_observe(flow, &view, 132) == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &key, &row) == 1 && row.quic == 1);
    CHECK(row.delta.bytes_out == 1250 && row.delta.packets_out == 2);

    row.key.protocol = 6;
    CHECK(store_flush(store, &row, 1) == -1); /* QUIC is only valid on UDP. */
    flow_destroy(flow);
    store_close(store);
}

int main(void) {
    test_detection(0);
    test_detection(1);
    test_aggregate(0);
    test_aggregate(1);
    puts("quic: ok");

    return 0;
}
