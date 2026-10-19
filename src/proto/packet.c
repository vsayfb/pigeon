#include "proto/packet.h"

int packet_parse(const uint8_t *frame, const size_t len, struct packet_view *out) {
    struct packet_view packet = { 0 };

    if (eth_parse(frame, len, &packet.eth) == -1) {
        return -1;
    }

    packet.kind = PACKET_ETHERNET;

    if (packet.eth.ethertype == ETHERTYPE_IPV6) {
        if (ipv6_parse(packet.eth.payload, packet.eth.payload_len, &packet.ip6) == -1) {
            return -1;
        }

        packet.kind = PACKET_IPV6;
    } else if (packet.eth.ethertype == ETHERTYPE_IPV4) {
        if (ipv4_parse(packet.eth.payload, packet.eth.payload_len, &packet.ip) == -1) {
            return -1;
        }

        packet.kind = PACKET_IPV4;
    } else {
        *out = packet;

        return 0;
    }

    const int ipv6 = packet.eth.ethertype == ETHERTYPE_IPV6;
    const uint16_t fragment = ipv6 ? packet.ip6.frag_offset : packet.ip.frag_offset;
    const uint8_t protocol = packet_protocol(&packet);

    if (fragment != 0) {
        *out = packet;

        return 0;
    }

    if (protocol == IP_PROTO_TCP) {
        const int rc = ipv6 ? tcp_parse_ipv6(&packet.ip6, &packet.transport.tcp)
                            : tcp_parse(&packet.ip, &packet.transport.tcp);

        if (rc == -1) {
            return -1;
        }

        packet.kind = PACKET_TCP;
    } else if (protocol == IP_PROTO_UDP) {
        const int rc = ipv6 ? udp_parse_ipv6(&packet.ip6, &packet.transport.udp)
                            : udp_parse(&packet.ip, &packet.transport.udp);

        if (rc == -1) {
            return -1;
        }

        packet.kind = PACKET_UDP;
    }

    *out = packet;

    return 0;
}

struct ip_addr packet_source(const struct packet_view *packet) {
    return packet->eth.ethertype == ETHERTYPE_IPV6 ? packet->ip6.src : ip_addr_v4(packet->ip.src);
}

struct ip_addr packet_destination(const struct packet_view *packet) {
    return packet->eth.ethertype == ETHERTYPE_IPV6 ? packet->ip6.dst : ip_addr_v4(packet->ip.dst);
}

uint8_t packet_protocol(const struct packet_view *packet) {
    return packet->eth.ethertype == ETHERTYPE_IPV6 ? packet->ip6.protocol : packet->ip.protocol;
}
