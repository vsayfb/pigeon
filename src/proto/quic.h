#ifndef PIGEON_PROTO_QUIC_H
#define PIGEON_PROTO_QUIC_H

#include <stddef.h>
#include <stdint.h>

#define QUIC_CID_MAX 20

struct quic_header {
    uint32_t version;
    uint8_t dcid[QUIC_CID_MAX];
    uint8_t scid[QUIC_CID_MAX];
    uint8_t dcid_len;
    uint8_t scid_len;
    int initial;
};

/* One bounded candidate per aggregate; local port and direction keep unrelated
 * UDP sockets from confirming each other. Classification does not affect keys. */
struct quic_probe {
    uint32_t version;
    uint8_t scid[QUIC_CID_MAX];
    uint8_t scid_len;
    uint16_t local_port;
    int outgoing;
    int64_t seen;
    int active;
};

/* Validate a complete first Initial/Handshake packet for QUIC v1/v2. Protected
 * bytes are opaque; this is not cryptographic authentication. Returns 1 for
 * evidence, 0 otherwise, leaving out untouched on 0. No port heuristics. */
int quic_parse_long(const uint8_t *data, size_t captured, struct quic_header *out);

/* Require opposite-direction, matching-CID evidence within 30 seconds of an
 * Initial in a fully captured datagram >=1200 bytes. Returns 1 on a match.
 * Unknown versions, one-way traffic and short headers never establish a label. */
int quic_observe(struct quic_probe *probe, const uint8_t *data, size_t captured,
                  size_t wire, uint16_t local_port, int outgoing, int64_t now);

#endif
