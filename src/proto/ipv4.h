#ifndef PIGEON_PROTO_IPV4_H
#define PIGEON_PROTO_IPV4_H

#include <stddef.h>
#include <stdint.h>

#define IPV4_MIN_HEADER_LEN 20
#define IPV4_STR_LEN        16      /* "255.255.255.255" plus the NUL */

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

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
    uint32_t src;               /* host byte order: 192.0.2.10 is 0xC000020A */
    uint32_t dst;
    const uint8_t *payload;     /* points into the buffer passed to ipv4_parse() */
    size_t payload_len;         /* bytes you may read at `payload` */
};

/*
 * Decodes the IPv4 header at the start of `data` (`len` readable bytes) into
 * `out`. `out->payload` points into `data`, so it is only valid as long as
 * `data` is.
 *
 * `payload_len` is the number of payload bytes that are both present in the
 * buffer and inside the packet the header describes: bytes past `total_len`
 * (Ethernet padding) are excluded, and so are bytes cut off by a short
 * capture. `total_len` still holds what the header claims, so
 * `total_len - header_len` is the payload size on the wire.
 *
 * The header checksum is not verified: NICs often fill it in after the
 * capture point, so outgoing packets would look corrupt.
 *
 * Returns 0 on success, -1 if the input is too short, is not version 4, has
 * an IHL below 5, has a header longer than `len`, or claims a `total_len`
 * smaller than its own header. `out` is untouched on failure.
 */
int ipv4_parse(const uint8_t *data, size_t len, struct ipv4_view *out);

/*
 * Writes `addr` (host byte order) into `buf` as dotted decimal and returns
 * `buf`, so the call can sit inside a printf argument list.
 */
const char *ipv4_addr_str(uint32_t addr, char buf[IPV4_STR_LEN]);

#endif
