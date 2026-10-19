#ifndef PIGEON_PROTO_ICMP_H
#define PIGEON_PROTO_ICMP_H

#include <stddef.h>
#include <stdint.h>

struct icmp_view {
    uint8_t type;
    uint8_t code;
    uint8_t header_len;
    const uint8_t *payload;
    size_t payload_len;
    size_t payload_wire_len;
};

/* Input is the IP-bounded upper-layer payload. Decode the common header,
 * including the next four type-specific bytes for IPv4 and IPv6 echo/errors.
 * Payload counts exclude this header. Captured data can be shorter than wire
 * data, but the header must be readable. No checksum validation or reassembly.
 * On failure, out is unchanged. Payload borrows the input buffer. */
int icmp_parse(const uint8_t *data, size_t captured, size_t wire, int ipv6,
               struct icmp_view *out);

#endif
