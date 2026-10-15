#ifndef PIGEON_PROTO_BYTES_H
#define PIGEON_PROTO_BYTES_H

#include <stdint.h>

/* Reads a big-endian (network byte order) 16-bit value from `p`. */
static inline uint16_t be16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

#endif
