#include <string.h>

#include "../t.h"
#include "proto/packet.h"
#include "proto/bytes.h"

static size_t build(uint8_t *frame, uint8_t protocol, int extension) {
    memset(frame, 0, 256);
    frame[12] = 0x86;
    frame[13] = 0xDD;
    frame[14] = 0x60;
    frame[20] = extension ? 0 : protocol;
    frame[21] = 64;
    frame[22] = frame[38] = 0x20;
    frame[23] = frame[39] = 0x01;
    frame[24] = frame[40] = 0x0D;
    frame[25] = frame[41] = 0xB8;
    frame[37] = 0x10;
    frame[53] = 0x42;

    size_t offset = 54;

    if (extension) {
        frame[offset] = protocol;
        offset += 8;
    }

    frame[offset] = 0xC0;
    frame[offset + 2] = 1;
    frame[offset + 3] = 0xBB;

    if (protocol == IP_PROTO_TCP) {
        frame[offset + 12] = 0x50;
        offset += 20;
    } else {
        frame[offset + 5] = 13;
        offset += 8;
    }

    memcpy(frame + offset, "hello", 5);
    offset += 5;
    frame[19] = (uint8_t)(offset - 54);

    return offset;
}

static void test_transport_and_lengths(void) {
    uint8_t frame[256];
    struct packet_view packet;

    for (int extension = 0; extension < 2; extension++) {
        const size_t size = build(frame, IP_PROTO_TCP, extension);

        CHECK(packet_parse(frame, size, &packet) == 0);
        CHECK(packet.kind == PACKET_TCP);
        CHECK(packet.ip6.src.family == 6);
        CHECK(packet.ip6.header_len == (size_t)(40 + 8 * extension));
        CHECK(packet.transport.tcp.src_port == 49152);
        CHECK(packet.transport.tcp.dst_port == 443);
        CHECK(packet.transport.tcp.payload_wire_len == 5);
        CHECK(packet.transport.tcp.payload_len == 5);
        CHECK(packet_parse(frame, size - 3, &packet) == 0);
        CHECK(packet.transport.tcp.payload_len == 2);
        CHECK(packet.transport.tcp.payload_wire_len == 5);
        CHECK(packet_parse(frame, size + 10, &packet) == 0);
        CHECK(packet.transport.tcp.payload_len == 5);

        for (size_t length = 0; length < size - 5; length++) {
            CHECK(packet_parse(frame, length, &packet) == -1);
        }
    }

    const size_t size = build(frame, IP_PROTO_UDP, 1);

    CHECK(packet_parse(frame, size, &packet) == 0);
    CHECK(packet.kind == PACKET_UDP);
    CHECK(packet.transport.udp.payload_wire_len == 5);
    CHECK(packet.transport.udp.payload_len == 5);
    CHECK(packet_parse(frame, size - 3, &packet) == 0);
    CHECK(packet.transport.udp.payload_len == 2);
    CHECK(packet.transport.udp.payload_wire_len == 5);
}

static void test_extensions_and_fragments(void) {
    uint8_t frame[256];
    struct packet_view packet;
    const uint8_t extensions[] = { 0, 43, 60, 44 };

    for (size_t i = 0; i < sizeof extensions; i++) {
        const size_t size = build(frame, IP_PROTO_TCP, 1);

        frame[20] = extensions[i];

        CHECK(packet_parse(frame, size, &packet) == 0);
        CHECK(packet.kind == PACKET_TCP);
    }

    size_t size = build(frame, IP_PROTO_TCP, 1);

    frame[20] = 44;
    frame[57] = 8;

    CHECK(packet_parse(frame, 62, &packet) == 0);
    CHECK(packet.kind == PACKET_IPV6);
    CHECK(packet.ip6.frag_offset == 8);

    size = build(frame, IP_PROTO_TCP, 1);
    frame[20] = 51;
    frame[55] = 0;

    CHECK(packet_parse(frame, size, &packet) == -1);

    /* AH length 1 represents a 12-byte header. */
    memmove(frame + 66, frame + 62, size - 62);
    frame[55] = 1;
    frame[19] += 4;

    CHECK(packet_parse(frame, size + 4, &packet) == 0);
    CHECK(packet.kind == PACKET_TCP);

    build(frame, IP_PROTO_TCP, 1);
    frame[55] = 255;

    CHECK(packet_parse(frame, 256, &packet) == -1);

    build(frame, IP_PROTO_TCP, 1);
    frame[20] = 44;
    frame[54] = 44;

    CHECK(packet_parse(frame, 256, &packet) == -1);
}

static void test_extension_limit_and_untouched_output(void) {
    uint8_t frame[256];
    struct ipv6_view ip;
    unsigned char before[sizeof ip];

    build(frame, IP_PROTO_TCP, 1);
    memset(frame + 54, 0, 17 * 8);
    frame[19] = 17 * 8;
    frame[54 + 16 * 8] = 59;
    memset(&ip, 0xAB, sizeof ip);
    memcpy(before, &ip, sizeof ip);

    CHECK(ipv6_parse(frame + 14, 40 + 17 * 8, &ip) == -1);
    CHECK(memcmp(before, &ip, sizeof ip) == 0);

    frame[19] = 16 * 8;
    frame[54 + 15 * 8] = 59;

    CHECK(ipv6_parse(frame + 14, 40 + 16 * 8, &ip) == 0);
    CHECK(ip.protocol == 59);
    CHECK(ip.payload_len == 0);
}

static void test_name_format_and_identity(void) {
    struct ip_addr a;
    struct ip_addr b;
    char text[IP_ADDR_STR_LEN];

    CHECK(ip_addr_parse("2001:db8::10", &a) == 0);
    CHECK(strcmp(ip_addr_str(&a, text), "2001:db8::10") == 0);
    CHECK(ip_addr_parse("2001:0db8:0:0:0:0:0:10", &b) == 0);
    CHECK(ip_addr_equal(&a, &b));
    CHECK(ip_addr_hash(&a) == ip_addr_hash(&b));
    CHECK(ip_addr_parse("::ffff:192.0.2.10", &a) == 0);

    b = ip_addr_v4(0xC000020A);

    CHECK(!ip_addr_equal(&a, &b));
    CHECK(ip_addr_parse("invalid", &a) == -1);
}

int main(void) {
    test_transport_and_lengths();
    test_extensions_and_fragments();
    test_name_format_and_identity();
    test_extension_limit_and_untouched_output();

    puts("ipv6: ok");

    return 0;
}
