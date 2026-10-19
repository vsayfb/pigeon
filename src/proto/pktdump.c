#include "proto/pktdump.h"

static void print_mac(FILE *stream, const uint8_t mac[ETH_ADDR_LEN]) {
    fprintf(stream, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void pktdump(FILE *stream, const struct packet_view *packet) {
    print_mac(stream, packet->eth.src);
    fprintf(stream, " > ");
    print_mac(stream, packet->eth.dst);
    fprintf(stream, " type=0x%04x", packet->eth.ethertype);

    for (unsigned i = 0; i < packet->eth.vlan_count; i++) {
        fprintf(stream, " vlan=%u(tpid=0x%04x)", packet->eth.vlans[i].tci & 0x0fff,
                packet->eth.vlans[i].tpid);
    }

    fputc('\n', stream);

    if (packet->kind == PACKET_ETHERNET) {
        return;
    }

    char src[IP_ADDR_STR_LEN];
    char dst[IP_ADDR_STR_LEN];
    uint16_t fragment;

    if (packet->eth.ethertype == ETHERTYPE_IPV6) {
        const struct ipv6_view *ip = &packet->ip6;

        fragment = ip->frag_offset;
        fprintf(stream, "    IPv6 %s > %s proto=%u hdr=%zu total=%u payload=%zu\n",
                ip_addr_str(&ip->src, src), ip_addr_str(&ip->dst, dst),
                ip->protocol, ip->header_len, ip->total_len, ip->payload_len);
    } else {
        const struct ipv4_view *ip = &packet->ip;

        fragment = ip->frag_offset;
        fprintf(stream, "    IPv4 %s > %s proto=%u hdr=%u total=%u payload=%zu\n",
                ipv4_addr_str(ip->src, src), ipv4_addr_str(ip->dst, dst),
                ip->protocol, ip->header_len, ip->total_len, ip->payload_len);
    }

    if (fragment != 0) {
        fprintf(stream, "    fragment at offset %u, no transport header\n", fragment);
    } else if (packet->kind == PACKET_TCP) {
        const struct tcp_view *tcp = &packet->transport.tcp;

        fprintf(stream, "    TCP %u > %u hdr=%u payload=%zu\n",
                tcp->src_port, tcp->dst_port, tcp->header_len, tcp->payload_wire_len);
    } else if (packet->kind == PACKET_UDP) {
        const struct udp_view *udp = &packet->transport.udp;

        fprintf(stream, "    UDP %u > %u payload=%zu\n",
                udp->src_port, udp->dst_port, udp->payload_wire_len);
    } else if (packet->kind == PACKET_ESP) {
        if (packet->esp.udp_encapsulated) {
            fprintf(stream, "    UDP %u > %u (ESP encapsulation)\n",
                    packet->transport.udp.src_port, packet->transport.udp.dst_port);
        }

        fprintf(stream, "    ESP spi=0x%08x sequence=%u protected=%zu\n",
                packet->esp.spi, packet->esp.sequence, packet->esp.payload_wire_len);
    } else if (packet->kind == PACKET_ICMP || packet->kind == PACKET_ICMPV6) {
        const struct icmp_view *icmp = &packet->transport.icmp;

        fprintf(stream, "    %s type=%u code=%u hdr=%u payload=%zu\n",
                protocol_name(packet_protocol(packet)), icmp->type, icmp->code,
                icmp->header_len, icmp->payload_wire_len);
    }
}
