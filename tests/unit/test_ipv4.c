#include <stdint.h>
#include <string.h>

#include "../t.h"
#include "capture/capture.h"
#include "proto/bytes.h"
#include "proto/ethernet.h"
#include "proto/ipv4.h"

#define CLIENT_IP 0xC000020Au   /* 192.0.2.10 */
#define SERVER_IP 0xC6336414u   /* 198.51.100.20 */

/* A valid packet: 20-byte header (IHL 5) + 4 payload bytes, TCP. */
static void make_packet(uint8_t pkt[24]) {
    static const uint8_t base[24] = {
        0x45, 0x00, 0x00, 0x18,     /* version 4, IHL 5 | tos | total_len 24 */
        0x00, 0x01, 0x00, 0x00,     /* id | flags + fragment offset */
        0x40, 0x06, 0x00, 0x00,     /* ttl 64 | protocol TCP | checksum */
        0xC0, 0x00, 0x02, 0x0A,     /* src 192.0.2.10 */
        0xC6, 0x33, 0x64, 0x14,     /* dst 198.51.100.20 */
        0xDE, 0xAD, 0xBE, 0xEF,     /* payload */
    };

    memcpy(pkt, base, sizeof base);
}

static void test_be32_reads_big_endian(void) {
    const uint8_t a[4] = { 0x01, 0x02, 0x03, 0x04 };
    const uint8_t b[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

    CHECK(be32(a) == 0x01020304u);
    CHECK(be32(b) == 0xFFFFFFFFu);
}

static void test_parses_ihl_5(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);

    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == 0);
    CHECK(ip.header_len == 20);
    CHECK(ip.protocol == IP_PROTO_TCP);
    CHECK(ip.total_len == 24);
    CHECK(ip.frag_offset == 0);
    CHECK(ip.src == CLIENT_IP);
    CHECK(ip.dst == SERVER_IP);
    CHECK(ip.payload == pkt + 20);
    CHECK(ip.payload_len == 4);
}

static void test_parses_ihl_6_with_options(void) {
    uint8_t pkt[28];
    struct ipv4_view ip;

    make_packet(pkt);                       /* fills the first 24 bytes */
    memmove(pkt + 24, pkt + 20, 4);         /* payload moves after the options */
    memset(pkt + 20, 0x01, 4);              /* 4 bytes of NOP options */
    pkt[0] = 0x46;                          /* IHL 6 */
    pkt[3] = 28;                            /* total_len */

    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == 0);
    CHECK(ip.header_len == 24);
    CHECK(ip.payload == pkt + 24);
    CHECK(ip.payload_len == 4);
    CHECK(ip.src == CLIENT_IP);             /* addresses stay at fixed offsets */
}

static void test_ihl_below_5_is_rejected(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);

    for (unsigned ihl = 0; ihl < 5; ihl++) {
        pkt[0] = (uint8_t)(0x40 | ihl);

        CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == -1);
    }
}

static void test_version_other_than_4_is_rejected(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);

    for (unsigned version = 0; version < 16; version++) {
        if (version == 4) {
            continue;
        }

        pkt[0] = (uint8_t)((version << 4) | 5);

        CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == -1);
    }
}

static void test_every_truncation_is_rejected(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);

    for (size_t len = 0; len < IPV4_MIN_HEADER_LEN; len++) {
        CHECK(ipv4_parse(pkt, len, &ip) == -1);
    }
}

static void test_header_longer_than_buffer_is_rejected(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);
    pkt[0] = 0x46;                          /* IHL 6: 24-byte header */

    CHECK(ipv4_parse(pkt, 23, &ip) == -1);  /* header incomplete */
    CHECK(ipv4_parse(pkt, 24, &ip) == 0);   /* header complete */
}

static void test_total_len_smaller_than_header_is_rejected(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);
    pkt[2] = 0x00;
    pkt[3] = 19;

    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == -1);

    pkt[3] = 20;                            /* header only, no payload */
    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == 0);
    CHECK(ip.payload_len == 0);
}

static void test_total_len_larger_than_caplen_is_clamped(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);
    pkt[2] = 0x05;                          /* total_len 0x05DC = 1500, */
    pkt[3] = 0xDC;                          /* only 24 bytes present */

    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == 0);
    CHECK(ip.total_len == 1500);            /* as stated in the header */
    CHECK(ip.payload_len == 4);             /* readable bytes */
}

static void test_bytes_past_total_len_are_not_payload(void) {
    uint8_t buf[60];
    struct ipv4_view ip;

    memset(buf, 0, sizeof buf);             /* zero padding after the packet */
    make_packet(buf);                       /* total_len 24, buffer is 60 */

    CHECK(ipv4_parse(buf, sizeof buf, &ip) == 0);
    CHECK(ip.total_len == 24);
    CHECK(ip.payload_len == 4);
}

static void test_fragment_offset_is_decoded(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);

    pkt[6] = 0x40;                          /* DF flag, offset 0 */
    pkt[7] = 0x00;

    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == 0);
    CHECK(ip.frag_offset == 0);

    pkt[6] = 0x20;                          /* MF flag, offset 0: first fragment */
    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == 0);
    CHECK(ip.frag_offset == 0);

    pkt[6] = 0x00;                          /* no flags, offset 185 * 8 */
    pkt[7] = 0xB9;

    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == 0);
    CHECK(ip.frag_offset == 1480);

    pkt[6] = 0x3F;                          /* MF + largest offset, 8191 * 8 */
    pkt[7] = 0xFF;

    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == 0);
    CHECK(ip.frag_offset == 65528);
}

static void test_failed_parse_leaves_out_untouched(void) {
    uint8_t pkt[24];
    struct ipv4_view ip;

    make_packet(pkt);
    pkt[0] = 0x60;
    memset(&ip, 0xAB, sizeof ip);

    CHECK(ipv4_parse(pkt, sizeof pkt, &ip) == -1);
    CHECK(ip.src == 0xABABABABu);
}

static void test_address_to_string(void) {
    char buf[IPV4_STR_LEN];

    CHECK(strcmp(ipv4_addr_str(CLIENT_IP, buf), "192.0.2.10") == 0);
    CHECK(strcmp(ipv4_addr_str(SERVER_IP, buf), "198.51.100.20") == 0);
    CHECK(strcmp(ipv4_addr_str(0, buf), "0.0.0.0") == 0);
    CHECK(strcmp(ipv4_addr_str(0xFFFFFFFFu, buf), "255.255.255.255") == 0);
}

struct replay {
    unsigned count;
};

/* Packets 0, 2 and 3 of the fixture go client -> server; 1 and 4 reply. */
static void check_fixture_frame(const uint8_t *data, uint32_t caplen,
                                uint32_t wirelen, int64_t timestamp, void *user) {
    struct replay *r = user;
    const int from_client = r->count == 0 || r->count == 2 || r->count == 3;
    struct eth_view eth;
    struct ipv4_view ip;

    (void)wirelen;
    (void)timestamp;

    CHECK(eth_parse(data, caplen, &eth) == 0);
    CHECK(ipv4_parse(eth.payload, eth.payload_len, &ip) == 0);

    CHECK(ip.header_len == 20);
    CHECK(ip.protocol == IP_PROTO_TCP);
    CHECK(ip.src == (from_client ? CLIENT_IP : SERVER_IP));
    CHECK(ip.dst == (from_client ? SERVER_IP : CLIENT_IP));
    CHECK(ip.total_len == caplen - ETH_HEADER_LEN);     /* no padding here */
    CHECK(ip.payload_len == (size_t)(ip.total_len - ip.header_len));
    CHECK(ip.payload == data + ETH_HEADER_LEN + ip.header_len);

    r->count++;
}

static void test_parses_every_fixture_frame(void) {
    struct replay r = { 0 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/tcp_handshake.pcap",
                           check_fixture_frame, &r) == 0);
    CHECK(r.count == 5);
}

int main(void) {
    test_be32_reads_big_endian();
    test_parses_ihl_5();
    test_parses_ihl_6_with_options();
    test_ihl_below_5_is_rejected();
    test_version_other_than_4_is_rejected();
    test_every_truncation_is_rejected();
    test_header_longer_than_buffer_is_rejected();
    test_total_len_smaller_than_header_is_rejected();
    test_total_len_larger_than_caplen_is_clamped();
    test_bytes_past_total_len_are_not_payload();
    test_fragment_offset_is_decoded();
    test_failed_parse_leaves_out_untouched();
    test_address_to_string();
    test_parses_every_fixture_frame();
    printf("ipv4: ok\n");

    return 0;
}
