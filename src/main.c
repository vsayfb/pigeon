#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "capture/capture.h"
#include "proto/ethernet.h"
#include "proto/ipv4.h"
#include "proto/transport.h"

#ifndef PIGEON_VERSION
#define PIGEON_VERSION "dev"
#endif

static void print_mac(const uint8_t mac[ETH_ADDR_LEN]) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Prints the Ethernet addresses and type of each frame. */
static void print_frame(const uint8_t *data, const uint32_t caplen,
                        const uint32_t wirelen, void *user) {
    unsigned long *count = user;
    struct eth_view eth;

    (*count)++;

    if (eth_parse(data, caplen, &eth) == -1) {
        printf("#%lu truncated frame, %u bytes\n", *count, caplen);

        return;
    }

    printf("#%lu ", *count);
    print_mac(eth.src);
    printf(" > ");
    print_mac(eth.dst);
    printf(" type=0x%04x caplen=%u wirelen=%u\n",
           eth.ethertype, caplen, wirelen);

    if (eth.ethertype == ETHERTYPE_IPV4) {
        struct ipv4_view ip;
        char src[IPV4_STR_LEN];
        char dst[IPV4_STR_LEN];

        if (ipv4_parse(eth.payload, eth.payload_len, &ip) == -1) {
            printf("    IPv4 malformed\n");

            return;
        }

        printf("    IPv4 %s > %s proto=%u hdr=%u total=%u payload=%zu\n",
               ipv4_addr_str(ip.src, src), ipv4_addr_str(ip.dst, dst),
               ip.protocol, ip.header_len, ip.total_len, ip.payload_len);

        if (ip.frag_offset != 0) {
            printf("    fragment at offset %u, no transport header\n",
                   ip.frag_offset);
        } else if (ip.protocol == IP_PROTO_TCP) {
            struct tcp_view tcp;

            if (tcp_parse(&ip, &tcp) == -1) {
                printf("    TCP malformed\n");
            } else {
                printf("    TCP %u > %u hdr=%u payload=%zu\n", tcp.src_port,
                       tcp.dst_port, tcp.header_len, tcp.payload_wire_len);
            }
        } else if (ip.protocol == IP_PROTO_UDP) {
            struct udp_view udp;

            if (udp_parse(&ip, &udp) == -1) {
                printf("    UDP malformed\n");
            } else {
                printf("    UDP %u > %u payload=%zu\n", udp.src_port,
                       udp.dst_port, udp.payload_wire_len);
            }
        }
    }
}

int main(const int argc, char **argv) {
    const int offline = argc == 3 && strcmp(argv[1], "-r") == 0;

    if (!offline && argc != 2) {
        fprintf(stderr, "pigeon %s\nusage: %s <interface>\n"
                        "       %s -r <file.pcap>\n",
                PIGEON_VERSION, argv[0], argv[0]);

        return 2;
    }

    unsigned long count = 0;
    int rc;

    if (offline) {
        rc = capture_run_file(argv[2], print_frame, &count);
    } else {
        fprintf(stderr, "pigeon %s capturing on %s\n", PIGEON_VERSION, argv[1]);
        rc = capture_run_live(argv[1], print_frame, &count);
    }

    fprintf(stderr, "pigeon stopped after %lu packets\n", count);

    return rc == 0 ? 0 : 1;
}
