#include <stdint.h>

#include "../t.h"
#include "capture/capture.h"

#define MAX_PACKETS 16

struct recorded {
    unsigned count;
    uint32_t caplen[MAX_PACKETS];
    uint32_t wirelen[MAX_PACKETS];
    int is_ipv4[MAX_PACKETS];
};

static void record(const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                   void *user) {
    struct recorded *r = user;

    if (r->count < MAX_PACKETS) {
        r->caplen[r->count] = caplen;
        r->wirelen[r->count] = wirelen;
        r->is_ipv4[r->count] = data[12] == 0x08 && data[13] == 0x00;
    }

    r->count++;
}

static void test_replays_every_packet_in_order(void) {
    static const uint32_t expected[] = { 54, 54, 54, 92, 92 };
    struct recorded r = { 0 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/tcp_handshake.pcap",
                           record, &r) == 0);
    CHECK(r.count == 5);

    for (unsigned i = 0; i < 5; i++) {
        CHECK(r.caplen[i] == expected[i]);
        CHECK(r.wirelen[i] == expected[i]);
        CHECK(r.is_ipv4[i]);
    }
}

static void test_missing_file_fails(void) {
    struct recorded r = { 0 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/does_not_exist.pcap",
                           record, &r) == -1);
    CHECK(r.count == 0);
}

int main(void) {
    test_replays_every_packet_in_order();
    test_missing_file_fails();
    printf("capture_file: ok\n");

    return 0;
}
