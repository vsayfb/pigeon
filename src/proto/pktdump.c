#include "proto/pktdump.h"

static void print_mac(FILE *stream, const uint8_t mac[ETH_ADDR_LEN]) {
    fprintf(stream, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void pktdump(FILE *stream, const struct packet_view *packet) {
    print_mac(stream, packet->eth.src);
    fprintf(stream, " > ");
    print_mac(stream, packet->eth.dst);
    fprintf(stream, " type=0x%04x\n", packet->eth.ethertype);

    if (packet->kind == PACKET_ETHERNET) {
        return;
    }

    const struct ipv4_view *ip = &packet->ip;
    char src[IPV4_STR_LEN];
    char dst[IPV4_STR_LEN];
    fprintf(stream, "    IPv4 %s > %s proto=%u hdr=%u total=%u payload=%zu\n",
            ipv4_addr_str(ip->src, src), ipv4_addr_str(ip->dst, dst),
            ip->protocol, ip->header_len, ip->total_len, ip->payload_len);

    if (ip->frag_offset != 0) {
        fprintf(stream, "    fragment at offset %u, no transport header\n",
                ip->frag_offset);
    } else if (packet->kind == PACKET_TCP) {
        const struct tcp_view *tcp = &packet->transport.tcp;
        fprintf(stream, "    TCP %u > %u hdr=%u payload=%zu\n",
                tcp->src_port, tcp->dst_port, tcp->header_len, tcp->payload_wire_len);
    } else if (packet->kind == PACKET_UDP) {
        const struct udp_view *udp = &packet->transport.udp;
        fprintf(stream, "    UDP %u > %u payload=%zu\n",
                udp->src_port, udp->dst_port, udp->payload_wire_len);
    }
}
