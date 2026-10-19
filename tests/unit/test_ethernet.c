#include <stdint.h>
#include <string.h>

#include "../t.h"
#include "capture/capture.h"
#include "proto/ethernet.h"

static const uint8_t SERVER_MAC[ETH_ADDR_LEN] = { 0x02, 0, 0, 0, 0, 0x02 };
static const uint8_t CLIENT_MAC[ETH_ADDR_LEN] = { 0x02, 0, 0, 0, 0, 0x01 };

static void test_parses_header_fields(void) {
    const uint8_t frame[] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,     /* dst */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,     /* src */
        0x08, 0x00,                             /* ethertype */
        0xde, 0xad, 0xbe, 0xef,                 /* payload */
    };

    struct eth_view eth;

    CHECK(eth_parse(frame, sizeof frame, &eth) == 0);
    CHECK(memcmp(eth.dst, SERVER_MAC, ETH_ADDR_LEN) == 0);
    CHECK(memcmp(eth.src, CLIENT_MAC, ETH_ADDR_LEN) == 0);
    CHECK(eth.ethertype == ETHERTYPE_IPV4);
    CHECK(eth.payload == frame + ETH_HEADER_LEN);
    CHECK(eth.payload_len == 4);
}

static void test_header_only_frame_has_empty_payload(void) {
    const uint8_t frame[ETH_HEADER_LEN] = { 0 };
    struct eth_view eth;

    CHECK(eth_parse(frame, sizeof frame, &eth) == 0);
    CHECK(eth.payload_len == 0);
}

static void test_every_truncation_is_rejected(void) {
    const uint8_t frame[ETH_HEADER_LEN] = { 0 };
    struct eth_view eth;

    for (size_t len = 0; len < ETH_HEADER_LEN; len++) {
        CHECK(eth_parse(frame, len, &eth) == -1);
    }
}

static void test_ethertypes_are_decoded(void) {
    uint8_t frame[ETH_HEADER_LEN] = { 0 };
    struct eth_view eth;

    frame[12] = 0x86;
    frame[13] = 0xDD;

    CHECK(eth_parse(frame, sizeof frame, &eth) == 0);
    CHECK(eth.ethertype == ETHERTYPE_IPV6);

    frame[12] = 0x08;
    frame[13] = 0x06;

    CHECK(eth_parse(frame, sizeof frame, &eth) == 0);
    CHECK(eth.ethertype == ETHERTYPE_ARP);
}

struct replay {
    unsigned count;
};

/* Packets 0, 2 and 3 of the fixture go client -> server; 1 and 4 reply. */
static void check_fixture_frame(const uint8_t *data, uint32_t caplen,
                                uint32_t wirelen, void *user) {
    struct replay *r = user;
    const int from_client = r->count == 0 || r->count == 2 || r->count == 3;
    struct eth_view eth;

    (void)wirelen;

    CHECK(eth_parse(data, caplen, &eth) == 0);
    CHECK(eth.ethertype == ETHERTYPE_IPV4);
    CHECK(eth.payload_len == caplen - ETH_HEADER_LEN);
    CHECK(memcmp(eth.src, from_client ? CLIENT_MAC : SERVER_MAC,
                 ETH_ADDR_LEN) == 0);
    CHECK(memcmp(eth.dst, from_client ? SERVER_MAC : CLIENT_MAC,
                 ETH_ADDR_LEN) == 0);

    r->count++;
}

static void test_parses_every_fixture_frame(void) {
    struct replay r = { 0 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/tcp_handshake.pcap",
                           check_fixture_frame, &r) == 0);
    CHECK(r.count == 5);
}

int main(void) {
    test_parses_header_fields();
    test_header_only_frame_has_empty_payload();
    test_every_truncation_is_rejected();
    test_ethertypes_are_decoded();
    test_parses_every_fixture_frame();
    printf("ethernet: ok\n");

    return 0;
}
