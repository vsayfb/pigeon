#ifndef PIGEON_PROTO_IPV4_H
#define PIGEON_PROTO_IPV4_H

#include <stddef.h>
#include <stdint.h>

#define IPV4_MIN_HEADER_LEN 20
#define IPV4_STR_LEN        16      /* "255.255.255.255" plus the NUL */

#include "proto/protocol.h"

/*
Decoded IPv4 header and the bytes that follow it.

IPv4 packet layout (selected fields; header is 20–60 bytes)

┌─────────┬─────────┬──────────┬─────────┬─────────┬─────────┐
│ Ver/IHL │ Tot Len │ Protocol │ Src IP  │ Dst IP  │ Payload │
│   1B    │   2B    │   1B     │   4B    │   4B    │         │
└─────────┴─────────┴──────────┴─────────┴─────────┴─────────┘
0         2         9          12        16        header_len
↓         ↓         ↓          ↓         ↓         ↓
data      data+2    data+9     data+12   data+16   data+header_len
 */
struct ipv4_view {
    uint8_t header_len;         /* in bytes: IHL * 4, between 20 and 60 */
    uint8_t protocol;           /* IP_PROTO_* */
    uint16_t total_len;         /* header + payload, as the header claims */
    uint16_t frag_offset;       /* bytes into the original datagram */
    uint32_t src;               /* host byte order: 192.0.2.10 is 0xC000020A */
    uint32_t dst;
    const uint8_t *payload;     /* points into the buffer passed to ipv4_parse() */
    size_t payload_len;         /* readable bytes at `payload` */
};

/*
 * Decodes the IPv4 header at the start of `data` (`len` readable bytes) into
 * `out`. `out->payload` points into `data` and is valid only as long as
 * `data` is.
 *
 * `payload_len` counts the payload bytes that are present in the buffer and
 * within `total_len`, so Ethernet padding and bytes cut off by a short
 * capture are excluded. `total_len - header_len` is the payload size on the
 * wire.
 *
 * `frag_offset` is the offset of this packet's data within the original
 * datagram: 0 for unfragmented packets and first fragments, non-zero for
 * later fragments, whose payload is not a transport header. Fragments are
 * not reassembled.
 *
 * The header checksum is not verified; NICs often fill it in after the
 * capture point, so outgoing packets would fail the check.
 *
 * Returns 0 on success. Returns -1, leaving `out` untouched, if the input is
 * shorter than the minimum header, the version is not 4, the IHL is below 5
 * or the header exceeds `len`, or `total_len` is smaller than the header.
 */
int ipv4_parse(const uint8_t *data, size_t len, struct ipv4_view *out);

/*
 * Formats `addr` (host byte order) as dotted decimal into `buf` and returns
 * `buf`.
 */
const char *ipv4_addr_str(uint32_t addr, char buf[IPV4_STR_LEN]);

#endif
