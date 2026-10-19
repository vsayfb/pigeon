#include <string.h>

#include "../t.h"
#include "capture/capture.h"
#include "proto/packet.h"

static void build_frame(uint8_t frame[64], uint8_t protocol) {
    memset(frame, 0, 64);
    frame[12] = 0x08;
    frame[14] = 0x45;
    frame[17] = 50;
    frame[23] = protocol;
    frame[34] = 0xC0;
    frame[37] = 80;

    if (protocol == IP_PROTO_TCP) {
        frame[46] = 0x50;
    } else {
        frame[39] = 30;
    }
}

static void test_layers_and_lengths(void) {
    uint8_t frame[64];
    struct packet_view packet;

    build_frame(frame, IP_PROTO_TCP);

    CHECK(packet_parse(frame, 64, &packet) == 0);
    CHECK(packet.kind == PACKET_TCP);
    CHECK(packet.transport.tcp.src_port == 49152);
    CHECK(packet.transport.tcp.dst_port == 80);
    CHECK(packet.transport.tcp.payload == frame + 54);
    CHECK(packet.transport.tcp.payload_len == 10);
    CHECK(packet.transport.tcp.payload_wire_len == 10);
    CHECK(packet_parse(frame, 56, &packet) == 0);
    CHECK(packet.transport.tcp.payload_len == 2);
    CHECK(packet.transport.tcp.payload_wire_len == 10);

    build_frame(frame, IP_PROTO_UDP);

    CHECK(packet_parse(frame, 64, &packet) == 0);
    CHECK(packet.kind == PACKET_UDP);
    CHECK(packet.transport.udp.payload == frame + 42);
    CHECK(packet.transport.udp.payload_len == 22);
    CHECK(packet.transport.udp.payload_wire_len == 22);

    frame[21] = 1;

    CHECK(packet_parse(frame, 34, &packet) == 0);
    CHECK(packet.kind == PACKET_IPV4);
    CHECK(packet.ip.frag_offset == 8);

    frame[21] = 0;
    frame[23] = IP_PROTO_ICMP;

    CHECK(packet_parse(frame, 34, &packet) == 0);
    CHECK(packet.kind == PACKET_IPV4);

    frame[12] = 0x86;
    frame[13] = 0xDD;

    CHECK(packet_parse(frame, 14, &packet) == 0);
    CHECK(packet.kind == PACKET_ETHERNET);
    CHECK(packet.eth.ethertype == ETHERTYPE_IPV6);
}

static void check_failure(const uint8_t *frame, size_t len) {
    struct packet_view packet;
    unsigned char before[sizeof packet];

    memset(&packet, 0xAB, sizeof packet);
    memcpy(before, &packet, sizeof packet);

    CHECK(packet_parse(frame, len, &packet) == -1);
    CHECK(memcmp(before, &packet, sizeof packet) == 0);
}

static void test_failures(void) {
    uint8_t frame[64];

    build_frame(frame, IP_PROTO_TCP);

    for (size_t len = 0; len < 54; len++) {
        check_failure(frame, len);
    }

    frame[46] = 0x40;
    check_failure(frame, 64);
    frame[14] = 0x44;
    check_failure(frame, 64);

    build_frame(frame, IP_PROTO_UDP);

    for (size_t len = 34; len < 42; len++) {
        check_failure(frame, len);
    }

    frame[39] = 7;
    check_failure(frame, 64);
}

struct replay {
    unsigned count;
    int short_frames;
};

static void check_frame(const uint8_t *data, uint32_t caplen,
                        uint32_t wirelen, void *user) {
    struct replay *r = user;
    struct packet_view packet;

    (void)wirelen;

    CHECK(packet_parse(data, caplen, &packet) == 0);
    CHECK(packet.ip.src == 0xC000020A || packet.ip.src == 0xC6336414);

    if (r->short_frames && r->count == 3) {
        CHECK(packet.kind == PACKET_UDP);
        CHECK(packet.transport.udp.payload_wire_len == 1);
    } else {
        const size_t expected = r->short_frames ? (r->count == 2 ? 1 : 0)
                                               : (r->count >= 3 ? 38 : 0);
        CHECK(packet.kind == PACKET_TCP);
        CHECK(packet.transport.tcp.payload_len == expected);
        CHECK(packet.transport.tcp.payload_wire_len == expected);
    }

    r->count++;
}

int main(void) {
    test_layers_and_lengths();
    test_failures();

    struct replay handshake = { 0, 0 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/tcp_handshake.pcap",
                          check_frame, &handshake) == 0);
    CHECK(handshake.count == 5);

    struct replay short_frames = { 0, 1 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/short_frames.pcap",
                          check_frame, &short_frames) == 0);
    CHECK(short_frames.count == 4);

    puts("packet: ok");

    return 0;
}
