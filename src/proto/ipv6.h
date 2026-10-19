#ifndef PIGEON_PROTO_IPV6_H
#define PIGEON_PROTO_IPV6_H

#include "proto/address.h"

#define IPV6_HEADER_LEN 40
#define IPV6_MAX_EXTENSIONS 16

struct ipv6_view {
    struct ip_addr src;
    struct ip_addr dst;
    uint8_t protocol;          /* final next-header value */
    uint16_t frag_offset;      /* bytes; later fragments have no transport header */
    uint32_t total_len;        /* base header plus declared IPv6 payload */
    size_t header_len;         /* base header plus decoded extensions */
    const uint8_t *payload;
    size_t payload_len;        /* readable upper-layer bytes, excluding padding */
    size_t payload_wire_len;   /* declared upper-layer bytes in this fragment */
};

/*
 * Decodes IPv6 and up to IPV6_MAX_EXTENSIONS hop-by-hop, routing, destination,
 * fragment and AH headers. ESP/unknown headers stop decoding. Later fragments
 * stop after their fragment header. No fragment reassembly or jumbograms.
 * len is readable bytes; payload borrows data for its lifetime.
 *
 * Returns 0 on success. Returns -1, leaving out untouched, for a bad version,
 * truncated/malformed headers, duplicate fragment headers or excessive chains.
 * Truncated payload is accepted when all supported headers are captured.
 */
int ipv6_parse(const uint8_t *data, size_t len, struct ipv6_view *out);

#endif
