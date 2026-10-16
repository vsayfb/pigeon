#ifndef PIGEON_PROTO_BYTES_H
#define PIGEON_PROTO_BYTES_H

#include <stdint.h>

/* Reads a big-endian (network byte order) 16-bit value from `p`. */
static inline uint16_t be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/*
 * Reads a big-endian (network byte order) 32-bit value from `p`.
 * Bytes are widened to uint32_t before shifting: shifting a promoted (signed)
 * int into the sign bit is undefined behavior.
 */
static inline uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

#endif
