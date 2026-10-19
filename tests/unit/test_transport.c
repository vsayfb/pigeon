#include <stdint.h>
#include <string.h>

#include "../t.h"
#include "capture/capture.h"
#include "proto/ethernet.h"
#include "proto/ipv4.h"
#include "proto/transport.h"

#define BUF_SIZE 256

/*
 * Builds an IPv4 packet (IHL 5) carrying a TCP segment: a `tcp_hl`-byte TCP
 * header (20..60, multiple of 4, extra bytes are NOP options) followed by
 * `payload_len` bytes of 0xAA. Ports 49152 -> 80. Returns the packet size.
 * The caller zero-initialises the buffer; bytes after the packet are padding.
 */
static size_t build_tcp(uint8_t *pkt, size_t tcp_hl, size_t payload_len) {
    const size_t total = IPV4_MIN_HEADER_LEN + tcp_hl + payload_len;
    uint8_t *tcp = pkt + IPV4_MIN_HEADER_LEN;

    pkt[0] = 0x45;
    pkt[2] = (uint8_t)(total >> 8);
    pkt[3] = (uint8_t)total;
    pkt[8] = 64;
    pkt[9] = IP_PROTO_TCP;

    tcp[0] = 0xC0; tcp[1] = 0x00;           /* src port 49152 */
    tcp[2] = 0x00; tcp[3] = 0x50;           /* dst port 80 */
    tcp[12] = (uint8_t)((tcp_hl / 4) << 4); /* data offset */
    tcp[13] = 0x10;                         /* ACK */
    memset(tcp + 20, 0x01, tcp_hl - 20);
    memset(tcp + tcp_hl, 0xAA, payload_len);

    return total;
}

/*
 * Builds an IPv4 packet (IHL 5) carrying a UDP datagram: an 8-byte header
 * whose length field is `udp_len` (independent of the real size) followed by
 * `payload_len` bytes of 0xBB. Ports 49152 -> 9999. Returns the packet size.
 */
static size_t build_udp(uint8_t *pkt, size_t udp_len, size_t payload_len) {
    const size_t total = IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + payload_len;
    uint8_t *udp = pkt + IPV4_MIN_HEADER_LEN;

    pkt[0] = 0x45;
    pkt[2] = (uint8_t)(total >> 8);
    pkt[3] = (uint8_t)total;
    pkt[8] = 64;
    pkt[9] = IP_PROTO_UDP;

    udp[0] = 0xC0; udp[1] = 0x00;           /* src port 49152 */
    udp[2] = 0x27; udp[3] = 0x0F;           /* dst port 9999 */
    udp[4] = (uint8_t)(udp_len >> 8);
    udp[5] = (uint8_t)udp_len;
    memset(udp + UDP_HEADER_LEN, 0xBB, payload_len);

    return total;
}

static void parse_ip(const uint8_t *pkt, size_t len, struct ipv4_view *ip) {
    CHECK(ipv4_parse(pkt, len, ip) == 0);
}

/* ---------------------------------------------------------------- TCP */

static void test_tcp_parses_fields(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct tcp_view tcp;
    const size_t len = build_tcp(pkt, 20, 5);

    parse_ip(pkt, len, &ip);

    CHECK(tcp_parse(&ip, &tcp) == 0);
    CHECK(tcp.src_port == 49152);
    CHECK(tcp.dst_port == 80);
    CHECK(tcp.header_len == 20);
    CHECK(tcp.payload == pkt + 40);
    CHECK(tcp.payload_len == 5);
    CHECK(tcp.payload_wire_len == 5);
    CHECK(tcp.payload[0] == 0xAA);
}

static void test_tcp_options_move_the_payload(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct tcp_view tcp;
    const size_t len = build_tcp(pkt, 32, 4);   /* data offset 8 */

    parse_ip(pkt, len, &ip);

    CHECK(tcp_parse(&ip, &tcp) == 0);
    CHECK(tcp.header_len == 32);
    CHECK(tcp.payload == pkt + 20 + 32);
    CHECK(tcp.payload_len == 4);
    CHECK(tcp.payload_wire_len == 4);
}

static void test_tcp_data_offset_below_5_is_rejected(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct tcp_view tcp;
    const size_t len = build_tcp(pkt, 20, 10);

    parse_ip(pkt, len, &ip);

    for (unsigned off = 0; off < 5; off++) {
        pkt[20 + 12] = (uint8_t)(off << 4);

        CHECK(tcp_parse(&ip, &tcp) == -1);
    }
}

static void test_tcp_header_longer_than_segment_is_rejected(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct tcp_view tcp;
    const size_t len = build_tcp(pkt, 20, 10);  /* segment is 30 bytes */

    parse_ip(pkt, len, &ip);

    pkt[20 + 12] = 0xF0;                        /* data offset 15: 60 bytes */
    CHECK(tcp_parse(&ip, &tcp) == -1);

    pkt[20 + 12] = 0x70;                        /* data offset 7: 28 bytes */
    CHECK(tcp_parse(&ip, &tcp) == 0);
    CHECK(tcp.header_len == 28);
    CHECK(tcp.payload_len == 2);
}

static void test_tcp_every_truncation_is_rejected(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct tcp_view tcp;

    build_tcp(pkt, 20, 0);

    for (size_t k = 0; k < TCP_MIN_HEADER_LEN; k++) {
        parse_ip(pkt, IPV4_MIN_HEADER_LEN + k, &ip);    /* k segment bytes */
        CHECK(tcp_parse(&ip, &tcp) == -1);
    }
}

static void test_tcp_padding_is_not_payload(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };      /* zero bytes after the packet: padding */
    struct ipv4_view ip;
    struct tcp_view tcp;
    size_t len = build_tcp(pkt, 20, 0);

    /* Pure ACK: 40-byte IP packet followed by 6 bytes of padding. */
    parse_ip(pkt, len + 6, &ip);

    CHECK(tcp_parse(&ip, &tcp) == 0);
    CHECK(tcp.payload_len == 0);
    CHECK(tcp.payload_wire_len == 0);

    memset(pkt, 0, sizeof pkt);
    len = build_tcp(pkt, 20, 1);        /* 1 payload byte, 5 bytes of padding */
    parse_ip(pkt, len + 5, &ip);

    CHECK(tcp_parse(&ip, &tcp) == 0);
    CHECK(tcp.payload_len == 1);
    CHECK(tcp.payload_wire_len == 1);
}

static void test_tcp_snaplen_cut_keeps_wire_size(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct tcp_view tcp;

    build_tcp(pkt, 20, 100);                    /* 140-byte IP packet */
    parse_ip(pkt, 50, &ip);                     /* 50 bytes captured */

    CHECK(tcp_parse(&ip, &tcp) == 0);
    CHECK(tcp.payload_len == 10);               /* readable bytes */
    CHECK(tcp.payload_wire_len == 100);         /* from the IP header */
}

static void test_tcp_later_fragment_is_rejected(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct tcp_view tcp;
    const size_t len = build_tcp(pkt, 20, 10);

    pkt[6] = 0x20;                              /* MF, offset 0: first fragment */
    parse_ip(pkt, len, &ip);

    CHECK(tcp_parse(&ip, &tcp) == 0);

    pkt[6] = 0x00;                              /* offset 185 * 8: later fragment */
    pkt[7] = 0xB9;
    parse_ip(pkt, len, &ip);

    CHECK(ip.frag_offset == 1480);
    CHECK(tcp_parse(&ip, &tcp) == -1);
}

static void test_tcp_failed_parse_leaves_out_untouched(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct tcp_view tcp;
    const size_t len = build_tcp(pkt, 20, 10);

    pkt[20 + 12] = 0x40;                        /* data offset 4 */
    parse_ip(pkt, len, &ip);
    memset(&tcp, 0xAB, sizeof tcp);

    CHECK(tcp_parse(&ip, &tcp) == -1);
    CHECK(tcp.src_port == 0xABAB);
}

/* ---------------------------------------------------------------- UDP */

static void test_udp_parses_fields(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;
    const size_t len = build_udp(pkt, UDP_HEADER_LEN + 5, 5);

    parse_ip(pkt, len, &ip);

    CHECK(udp_parse(&ip, &udp) == 0);
    CHECK(udp.src_port == 49152);
    CHECK(udp.dst_port == 9999);
    CHECK(udp.payload == pkt + 28);
    CHECK(udp.payload_len == 5);
    CHECK(udp.payload_wire_len == 5);
    CHECK(udp.payload[0] == 0xBB);
}

static void test_udp_empty_payload_is_valid(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;
    const size_t len = build_udp(pkt, UDP_HEADER_LEN, 0);

    parse_ip(pkt, len, &ip);

    CHECK(udp_parse(&ip, &udp) == 0);
    CHECK(udp.payload_len == 0);
    CHECK(udp.payload_wire_len == 0);
}

static void test_udp_length_below_header_is_rejected(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;

    for (size_t udp_len = 0; udp_len < UDP_HEADER_LEN; udp_len++) {
        const size_t len = build_udp(pkt, udp_len, 4);

        parse_ip(pkt, len, &ip);

        CHECK(udp_parse(&ip, &udp) == -1);
    }
}

static void test_udp_every_truncation_is_rejected(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;

    build_udp(pkt, UDP_HEADER_LEN, 0);

    for (size_t k = 0; k < UDP_HEADER_LEN; k++) {
        parse_ip(pkt, IPV4_MIN_HEADER_LEN + k, &ip);

        CHECK(udp_parse(&ip, &udp) == -1);
    }
}

static void test_udp_length_larger_than_ip_payload_uses_ip(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;
    const size_t len = build_udp(pkt, 1000, 5);     /* UDP length 1000, 5 payload bytes */

    parse_ip(pkt, len, &ip);

    CHECK(udp_parse(&ip, &udp) == 0);
    CHECK(udp.payload_len == 5);
    CHECK(udp.payload_wire_len == 5);
}

static void test_udp_length_smaller_than_ip_payload_uses_udp(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;
    const size_t len = build_udp(pkt, UDP_HEADER_LEN + 3, 10);

    parse_ip(pkt, len, &ip);

    CHECK(udp_parse(&ip, &udp) == 0);
    CHECK(udp.payload_len == 3);                    /* 7 trailing bytes ignored */
    CHECK(udp.payload_wire_len == 3);
}

static void test_udp_padding_is_not_payload(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;
    const size_t len = build_udp(pkt, UDP_HEADER_LEN + 1, 1);

    parse_ip(pkt, len + 17, &ip);                   /* 17 padding bytes */

    CHECK(udp_parse(&ip, &udp) == 0);
    CHECK(udp.payload_len == 1);
    CHECK(udp.payload_wire_len == 1);
}

static void test_udp_snaplen_cut_keeps_wire_size(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;

    build_udp(pkt, UDP_HEADER_LEN + 100, 100);
    parse_ip(pkt, 20 + 8 + 10, &ip);

    CHECK(udp_parse(&ip, &udp) == 0);
    CHECK(udp.payload_len == 10);
    CHECK(udp.payload_wire_len == 100);
}

static void test_udp_later_fragment_is_rejected(void) {
    uint8_t pkt[BUF_SIZE] = { 0 };
    struct ipv4_view ip;
    struct udp_view udp;
    const size_t len = build_udp(pkt, UDP_HEADER_LEN + 5, 5);

    pkt[7] = 0xB9;
    parse_ip(pkt, len, &ip);

    CHECK(udp_parse(&ip, &udp) == -1);
}

/* ------------------------------------------------------------ fixtures */

struct replay {
    unsigned count;
};

/* Packets 0, 2 and 3 of the fixture go client -> server; 1 and 4 reply. */
static void check_handshake_frame(const uint8_t *data, uint32_t caplen,
                                  uint32_t wirelen, int64_t timestamp, void *user) {
    struct replay *r = user;
    const int from_client = r->count == 0 || r->count == 2 || r->count == 3;
    const size_t expected_payload = r->count >= 3 ? 38 : 0;
    struct eth_view eth;
    struct ipv4_view ip;
    struct tcp_view tcp;

    (void)wirelen;
    (void)timestamp;

    CHECK(eth_parse(data, caplen, &eth) == 0);
    CHECK(ipv4_parse(eth.payload, eth.payload_len, &ip) == 0);
    CHECK(ip.protocol == IP_PROTO_TCP);
    CHECK(tcp_parse(&ip, &tcp) == 0);

    CHECK(tcp.src_port == (from_client ? 49152 : 80));
    CHECK(tcp.dst_port == (from_client ? 80 : 49152));
    CHECK(tcp.header_len == 20);
    CHECK(tcp.payload_len == expected_payload);
    CHECK(tcp.payload_wire_len == expected_payload);
    CHECK(tcp.payload == data + ETH_HEADER_LEN + ip.header_len + tcp.header_len);

    r->count++;
}

static void test_handshake_fixture(void) {
    struct replay r = { 0 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/tcp_handshake.pcap",
                           check_handshake_frame, &r) == 0);
    CHECK(r.count == 5);
}

/*
 * Every frame is 60 bytes including padding. Payload sizes must come from the
 * IP header: subtracting header lengths from `caplen` would include the
 * padding.
 */
static void check_short_frame(const uint8_t *data, uint32_t caplen,
                              uint32_t wirelen, int64_t timestamp, void *user) {
    struct replay *r = user;
    struct eth_view eth;
    struct ipv4_view ip;

    (void)wirelen;
    (void)timestamp;

    CHECK(caplen == 60);
    CHECK(eth_parse(data, caplen, &eth) == 0);
    CHECK(ipv4_parse(eth.payload, eth.payload_len, &ip) == 0);

    /* Bytes after the IP header, padding included. */
    const size_t after_ip = caplen - ETH_HEADER_LEN - ip.header_len;

    if (r->count < 3) {
        struct tcp_view tcp;
        const size_t expected = r->count == 2 ? 1 : 0;

        CHECK(ip.protocol == IP_PROTO_TCP);
        CHECK(tcp_parse(&ip, &tcp) == 0);

        CHECK(after_ip - tcp.header_len == 6);          /* includes padding */
        CHECK(tcp.payload_wire_len == expected);        /* excludes it */
        CHECK(tcp.payload_len == expected);

        if (expected == 1) {
            CHECK(tcp.payload[0] == 'x');
        }
    } else {
        struct udp_view udp;

        CHECK(ip.protocol == IP_PROTO_UDP);
        CHECK(udp_parse(&ip, &udp) == 0);

        CHECK(after_ip - UDP_HEADER_LEN == 18);         /* includes padding */
        CHECK(udp.payload_wire_len == 1);               /* excludes it */
        CHECK(udp.payload_len == 1);
        CHECK(udp.payload[0] == 'y');
        CHECK(udp.src_port == 49152);
        CHECK(udp.dst_port == 9999);
    }

    r->count++;
}

static void test_short_frames_fixture(void) {
    struct replay r = { 0 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/short_frames.pcap",
                           check_short_frame, &r) == 0);
    CHECK(r.count == 4);
}

int main(void) {
    test_tcp_parses_fields();
    test_tcp_options_move_the_payload();
    test_tcp_data_offset_below_5_is_rejected();
    test_tcp_header_longer_than_segment_is_rejected();
    test_tcp_every_truncation_is_rejected();
    test_tcp_padding_is_not_payload();
    test_tcp_snaplen_cut_keeps_wire_size();
    test_tcp_later_fragment_is_rejected();
    test_tcp_failed_parse_leaves_out_untouched();

    test_udp_parses_fields();
    test_udp_empty_payload_is_valid();
    test_udp_length_below_header_is_rejected();
    test_udp_every_truncation_is_rejected();
    test_udp_length_larger_than_ip_payload_uses_ip();
    test_udp_length_smaller_than_ip_payload_uses_udp();
    test_udp_padding_is_not_payload();
    test_udp_snaplen_cut_keeps_wire_size();
    test_udp_later_fragment_is_rejected();

    test_handshake_fixture();
    test_short_frames_fixture();
    printf("transport: ok\n");

    return 0;
}
