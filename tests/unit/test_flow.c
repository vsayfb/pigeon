#include <errno.h>

#include "../t.h"
#include "flow/flow.h"

#define LOCAL_IP  UINT32_C(0xC000020A)
#define REMOTE_IP UINT32_C(0xC6336414)

static struct packet_view make_packet(enum packet_kind kind, int outgoing,
                                      uint16_t local_port, uint16_t remote_port) {
    struct packet_view packet = { 0 };

    packet.kind = kind;
    packet.ip.src = outgoing ? LOCAL_IP : REMOTE_IP;
    packet.ip.dst = outgoing ? REMOTE_IP : LOCAL_IP;
    packet.ip.protocol = kind == PACKET_TCP ? IP_PROTO_TCP : IP_PROTO_UDP;

    if (kind == PACKET_TCP) {
        packet.transport.tcp.src_port = outgoing ? local_port : remote_port;
        packet.transport.tcp.dst_port = outgoing ? remote_port : local_port;
    } else {
        packet.transport.udp.src_port = outgoing ? local_port : remote_port;
        packet.transport.udp.dst_port = outgoing ? remote_port : local_port;
    }

    return packet;
}

static void test_direction_and_local_ports(enum packet_kind kind) {
    struct flow *flow = flow_create(LOCAL_IP, 16, 8);
    struct packet_view packet = make_packet(kind, 1, 49152, 443);

    const struct flow_key key = {
        .us_ip = ip_addr_v4(LOCAL_IP),
        .remote_ip = ip_addr_v4(REMOTE_IP),
        .remote_port = 443,
        .protocol = kind == PACKET_TCP ? IP_PROTO_TCP : IP_PROTO_UDP
    };

    CHECK(flow != NULL);
    CHECK(flow_count(flow) == 0);
    CHECK(flow_find(flow, &key) == NULL);
    CHECK(flow_observe(flow, &packet, 100) == 1);

    const struct flow_entry *entry = flow_find(flow, &key);

    CHECK(entry != NULL);
    CHECK(flow_key_equal(flow_entry_key(entry), &key));

    packet = make_packet(kind, 0, 49152, 443);

    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_find(flow, &key) == entry);

    packet = make_packet(kind, 1, 52000, 443);

    CHECK(flow_observe(flow, &packet, 100) == 1);

    packet = make_packet(kind, 0, 52000, 443);

    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_find(flow, &key) == entry);
    CHECK(flow_count(flow) == 1);

    flow_destroy(flow);
}

static void test_incoming_first_and_distinct_services(void) {
    struct flow *flow = flow_create(LOCAL_IP, 1, 8);
    struct packet_view packet = make_packet(PACKET_UDP, 0, 49152, 53);

    const struct flow_key key = {
        .us_ip = ip_addr_v4(LOCAL_IP),
        .remote_ip = ip_addr_v4(REMOTE_IP),
        .remote_port = 53,
        .protocol = IP_PROTO_UDP
    };

    CHECK(flow != NULL);
    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_find(flow, &key) != NULL);

    packet = make_packet(PACKET_UDP, 1, 49152, 53);

    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_count(flow) == 1);

    packet = make_packet(PACKET_TCP, 1, 49152, 53);

    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_count(flow) == 2);

    packet = make_packet(PACKET_UDP, 1, 49152, 443);

    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_count(flow) == 3);

    packet.ip.dst++;

    CHECK(flow_observe(flow, &packet, 100) == 1);
    CHECK(flow_count(flow) == 4);

    flow_destroy(flow);
}

static void test_ignored_packets(void) {
    struct flow *flow = flow_create(LOCAL_IP, 16, 8);
    struct packet_view packet = make_packet(PACKET_TCP, 1, 49152, 443);

    CHECK(flow != NULL);
    CHECK(flow_observe(flow, &packet, 100) == 1);

    const struct flow_key key = {
        .us_ip = ip_addr_v4(LOCAL_IP),
        .remote_ip = ip_addr_v4(REMOTE_IP),
        .remote_port = 443,
        .protocol = IP_PROTO_TCP
    };

    const struct flow_entry *entry = flow_find(flow, &key);

    packet.ip.src = REMOTE_IP + 1;

    CHECK(flow_observe(flow, &packet, 100) == 0);

    packet.ip.src = LOCAL_IP;
    packet.ip.dst = LOCAL_IP;

    CHECK(flow_observe(flow, &packet, 100) == 0);

    packet = make_packet(PACKET_TCP, 1, 49152, 443);
    packet.kind = PACKET_IPV4;
    packet.ip.frag_offset = 8;

    CHECK(flow_observe(flow, &packet, 100) == 0);

    packet.ip.frag_offset = 0;
    packet.ip.protocol = IP_PROTO_ICMP;

    CHECK(flow_observe(flow, &packet, 100) == 0);

    packet.kind = PACKET_ETHERNET;

    CHECK(flow_observe(flow, &packet, 100) == 0);
    CHECK(flow_count(flow) == 1);
    CHECK(flow_find(flow, &key) == entry);

    flow_destroy(flow);
}

static void test_deltas_and_times(enum packet_kind kind) {
    struct flow *flow = flow_create(LOCAL_IP, 1, 4);
    struct packet_view packet = make_packet(kind, 1, 49152, 443);

    const struct flow_key key = {
        .us_ip = ip_addr_v4(LOCAL_IP),
        .remote_ip = ip_addr_v4(REMOTE_IP),
        .remote_port = 443,
        .protocol = kind == PACKET_TCP ? IP_PROTO_TCP : IP_PROTO_UDP
    };

    CHECK(flow != NULL);

    /* A zero-payload packet at timestamp zero still initializes the entry. */
    CHECK(flow_observe(flow, &packet, 0) == 1);

    if (kind == PACKET_TCP) {
        packet.transport.tcp.payload_len = 2;
        packet.transport.tcp.payload_wire_len = 100;
    } else {
        packet.transport.udp.payload_len = 2;
        packet.transport.udp.payload_wire_len = 100;
    }

    CHECK(flow_observe(flow, &packet, 30) == 1);

    packet = make_packet(kind, 0, 52000, 443);

    if (kind == PACKET_TCP) {
        packet.transport.tcp.payload_wire_len = 50;
    } else {
        packet.transport.udp.payload_wire_len = 50;
    }

    CHECK(flow_observe(flow, &packet, 20) == 1);
    CHECK(flow_observe(flow, &packet, -1) == 1);

    const struct flow_entry *entry = flow_find(flow, &key);

    CHECK(entry != NULL);

    const struct flow_delta *delta = flow_entry_delta(entry);

    CHECK(delta->packets_out == 2);
    CHECK(delta->packets_in == 2);
    CHECK(delta->bytes_out == 100);
    CHECK(delta->bytes_in == 100);
    CHECK(delta->first_seen == -1);
    CHECK(delta->last_seen == 30);

    packet.ip.src = REMOTE_IP + 1;
    packet.ip.dst = REMOTE_IP + 2;

    CHECK(flow_observe(flow, &packet, 90) == 0);
    CHECK(delta->packets_out == 2);
    CHECK(delta->packets_in == 2);
    CHECK(delta->last_seen == 30);

    flow_destroy(flow);
}

struct handoff {
    unsigned calls;
    int fail;
    struct flow_key key;
    struct flow_delta delta;
};

static int save_evicted(const struct flow_entry *entry, void *user) {
    struct handoff *handoff = user;

    handoff->calls++;
    handoff->key = *flow_entry_key(entry);
    handoff->delta = *flow_entry_delta(entry);

    if (handoff->fail) {
        errno = EIO;

        return -1;
    }

    return 0;
}

static void test_eviction_handoff_and_touch(void) {
    struct flow *flow = flow_create(LOCAL_IP, 1, 2);
    struct packet_view packet = make_packet(PACKET_TCP, 1, 49152, 443);
    struct handoff handoff = { 0 };

    const struct flow_key a = {
        .us_ip = ip_addr_v4(LOCAL_IP), .remote_ip = ip_addr_v4(REMOTE_IP),
        .remote_port = 443, .protocol = IP_PROTO_TCP
    };

    struct flow_key b = a;
    struct flow_key c = a;

    b.remote_port = 80;
    c.remote_port = 22;

    CHECK(flow != NULL);
    CHECK(flow_observe(flow, &packet, 10) == 1);

    packet = make_packet(PACKET_TCP, 0, 49152, 80);
    packet.transport.tcp.payload_wire_len = 40;

    CHECK(flow_observe(flow, &packet, 11) == 1);

    const struct flow_entry *a_entry = flow_find(flow, &a);
    const struct flow_entry *b_entry = flow_find(flow, &b);

    packet = make_packet(PACKET_TCP, 0, 52000, 443);

    CHECK(flow_observe(flow, &packet, 12) == 1);

    packet = make_packet(PACKET_TCP, 1, 49152, 22);

    CHECK(flow_observe(flow, &packet, 13) == -1);
    CHECK(errno == ENOSPC);
    CHECK(flow_find(flow, &a) == a_entry);
    CHECK(flow_find(flow, &b) == b_entry);
    CHECK(flow_find(flow, &c) == NULL);
    CHECK(flow_count(flow) == 2);

    handoff.fail = 1;
    flow_set_eviction_handler(flow, save_evicted, &handoff);

    CHECK(flow_observe(flow, &packet, 14) == -1);
    CHECK(errno == EIO);
    CHECK(handoff.calls == 1);
    CHECK(flow_find(flow, &b) == b_entry);
    CHECK(flow_find(flow, &c) == NULL);

    handoff.fail = 0;

    CHECK(flow_observe(flow, &packet, 15) == 1);
    CHECK(handoff.calls == 2);
    CHECK(flow_key_equal(&handoff.key, &b));
    CHECK(handoff.delta.packets_in == 1);
    CHECK(handoff.delta.packets_out == 0);
    CHECK(handoff.delta.bytes_in == 40);
    CHECK(handoff.delta.first_seen == 11);
    CHECK(handoff.delta.last_seen == 11);
    CHECK(flow_find(flow, &a) == a_entry);
    CHECK(flow_find(flow, &b) == NULL);
    CHECK(flow_count(flow) == 2);

    const struct flow_delta *delta = flow_entry_delta(flow_find(flow, &c));

    CHECK(delta->packets_out == 1);
    CHECK(delta->bytes_out == 0);
    CHECK(delta->first_seen == 15);

    flow_set_eviction_handler(flow, NULL, NULL);
    flow_destroy(flow);
}

int main(void) {
    CHECK(flow_create(LOCAL_IP, 0, 8) == NULL);
    CHECK(errno == EINVAL);
    CHECK(flow_create(LOCAL_IP, 16, 0) == NULL);
    CHECK(errno == EINVAL);

    flow_destroy(NULL);

    test_direction_and_local_ports(PACKET_TCP);
    test_direction_and_local_ports(PACKET_UDP);
    test_incoming_first_and_distinct_services();
    test_ignored_packets();
    test_deltas_and_times(PACKET_TCP);
    test_deltas_and_times(PACKET_UDP);
    test_eviction_handoff_and_touch();

    puts("flow: ok");

    return 0;
}
