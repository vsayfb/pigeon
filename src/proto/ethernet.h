#ifndef PIGEON_PROTO_ETHERNET_H
#define PIGEON_PROTO_ETHERNET_H

#include <stddef.h>
#include <stdint.h>

#define ETH_ADDR_LEN   6
#define ETH_HEADER_LEN 14

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV6 0x86DD

/* Decoded Ethernet II header and the bytes that follow it. */
struct eth_view {
    uint8_t dst[ETH_ADDR_LEN];
    uint8_t src[ETH_ADDR_LEN];
    uint16_t ethertype;         /* host byte order */
    const uint8_t *payload;     /* points into the frame passed to eth_parse() */
    size_t payload_len;
};

/*
 * Decodes the Ethernet II header at the start of `frame` (`len` readable
 * bytes) into `out`. `out->payload` points into `frame`, so it is only
 * valid as long as `frame` is.
 *
 * Returns 0 on success, -1 if `len` is shorter than ETH_HEADER_LEN.
 */
int eth_parse(const uint8_t *frame, size_t len, struct eth_view *out);

#endif
