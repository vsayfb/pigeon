#include <string.h>

#include "../t.h"
#include "proto/packet.h"
#include "capture/capture.h"

static size_t tag(const uint8_t *frame, size_t len, uint8_t *out, unsigned count) {
    CHECK(len >= ETH_HEADER_LEN && len + 4 * count <= 4096);
    memcpy(out, frame, 12);

    size_t offset = 12;

    for (unsigned i = 0; i < count; i++) {
        const uint16_t type = i == 0 && count > 1 ? ETHERTYPE_VLAN_SERVICE : ETHERTYPE_VLAN;
        const uint16_t tci = (uint16_t)(0xb000 | (100 + i));

        out[offset++] = (uint8_t)(type >> 8);
        out[offset++] = (uint8_t)type;
        out[offset++] = (uint8_t)(tci >> 8);
        out[offset++] = (uint8_t)tci;
    }

    memcpy(out + offset, frame + 12, len - 12);

    return len + 4 * count;
}

static void bounds(void) {
    const uint8_t frame[16] = { [12] = 0xaa, [13] = 0x55, [14] = 1, [15] = 2 };
    uint8_t tagged[4096];
    struct eth_view eth;
    const size_t len = tag(frame, sizeof frame, tagged, ETH_MAX_VLAN_TAGS);

    CHECK(eth_parse(tagged, len, &eth) == 0);
    CHECK(eth.vlan_count == ETH_MAX_VLAN_TAGS);
    CHECK(eth.ethertype == 0xaa55);
    CHECK(eth.payload == tagged + 14 + 4 * ETH_MAX_VLAN_TAGS);
    CHECK(eth.payload_len == 2);
    CHECK(eth.vlans[0].tpid == ETHERTYPE_VLAN_SERVICE);
    CHECK((eth.vlans[0].tci & 0x0fff) == 100);
    CHECK((eth.vlans[0].tci >> 13) == 5);

    for (size_t cut = 0; cut < len - 2; cut++) {
        struct eth_view before;

        memset(&eth, 0xa5, sizeof eth);
        memcpy(&before, &eth, sizeof eth);
        CHECK(eth_parse(tagged, cut, &eth) == -1);
        CHECK(memcmp(&before, &eth, sizeof eth) == 0);
    }

    const size_t excessive = tag(frame, sizeof frame, tagged, ETH_MAX_VLAN_TAGS + 1);

    CHECK(eth_parse(tagged, excessive, &eth) == -1);
}

static void check(const uint8_t *data, uint32_t captured, uint32_t wire,
                    int64_t timestamp, void *user) {
    struct packet_view plain;
    uint8_t tagged[4096];
    unsigned *count = user;

    (void)wire;
    (void)timestamp;
    CHECK(packet_parse(data, captured, &plain) == 0);

    for (unsigned tags = 1; tags <= 2; tags++) {
        struct packet_view packet;
        const size_t len = tag(data, captured, tagged, tags);

        CHECK(packet_parse(tagged, len, &packet) == 0);
        CHECK(packet.kind == plain.kind);
        CHECK(packet.eth.vlan_count == tags);
        CHECK(packet.eth.ethertype == plain.eth.ethertype);
        CHECK(packet_protocol(&packet) == packet_protocol(&plain));

        const struct ip_addr source = packet_source(&packet);
        const struct ip_addr original = packet_source(&plain);

        CHECK(ip_addr_equal(&source, &original));

        if (packet.kind == PACKET_TCP) {
            CHECK(packet.transport.tcp.payload_wire_len == plain.transport.tcp.payload_wire_len);
            CHECK(packet.transport.tcp.payload_len == plain.transport.tcp.payload_len);
        } else if (packet.kind == PACKET_UDP) {
            CHECK(packet.transport.udp.payload_wire_len == plain.transport.udp.payload_wire_len);
            CHECK(packet.transport.udp.payload_len == plain.transport.udp.payload_len);
        }
    }

    (*count)++;
}

int main(void) {
    unsigned count = 0;

    bounds();
    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/short_frames.pcap", check, &count) == 0);
    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/ipv6_conversations.pcap", check, &count) == 0);
    CHECK(count == 10);
    puts("vlan: ok");

    return 0;
}
