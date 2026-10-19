#ifndef PIGEON_FLOW_KEY_H
#define PIGEON_FLOW_KEY_H

#include <stddef.h>
#include <stdint.h>

/* Conversation identity. Addresses and port are in host byte order. */
struct flow_key {
    uint32_t us_ip;
    uint32_t remote_ip;
    uint16_t remote_port;
    uint8_t protocol;
};

static inline int flow_key_equal(const struct flow_key *a, const struct flow_key *b) {
    return a->us_ip == b->us_ip &&
           a->remote_ip == b->remote_ip &&
           a->remote_port == b->remote_port &&
           a->protocol == b->protocol;
}

/* FNV-1a over the key fields, most significant byte first; excludes padding. */
static inline uint32_t flow_key_hash(const struct flow_key *key) {
    const uint8_t bytes[] = {
        (uint8_t)(key->us_ip >> 24),
        (uint8_t)(key->us_ip >> 16),
        (uint8_t)(key->us_ip >> 8),
        (uint8_t)key->us_ip,
        (uint8_t)(key->remote_ip >> 24),
        (uint8_t)(key->remote_ip >> 16),
        (uint8_t)(key->remote_ip >> 8),
        (uint8_t)key->remote_ip,
        (uint8_t)(key->remote_port >> 8),
        (uint8_t)key->remote_port,
        key->protocol
    };

    uint32_t hash = UINT32_C(2166136261);

    for (size_t i = 0; i < sizeof bytes; i++) {
        hash ^= bytes[i];
        hash *= UINT32_C(16777619);
    }

    return hash;
}

#endif
