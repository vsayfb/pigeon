#include "proto/packet.h"

int packet_parse(const uint8_t *frame, const size_t len, struct packet_view *out) {
    struct packet_view packet = { 0 };

    if (eth_parse(frame, len, &packet.eth) == -1) {
        return -1;
    }

    packet.kind = PACKET_ETHERNET;

    if (packet.eth.ethertype != ETHERTYPE_IPV4) {
        *out = packet;

        return 0;
    }

    if (ipv4_parse(packet.eth.payload, packet.eth.payload_len, &packet.ip) == -1) {
        return -1;
    }

    packet.kind = PACKET_IPV4;

    if (packet.ip.frag_offset != 0) {
        *out = packet;

        return 0;
    }

    if (packet.ip.protocol == IP_PROTO_TCP) {
        if (tcp_parse(&packet.ip, &packet.transport.tcp) == -1) {
            return -1;
        }

        packet.kind = PACKET_TCP;
    } else if (packet.ip.protocol == IP_PROTO_UDP) {
        if (udp_parse(&packet.ip, &packet.transport.udp) == -1) {
            return -1;
        }

        packet.kind = PACKET_UDP;
    }

    *out = packet;

    return 0;
}
