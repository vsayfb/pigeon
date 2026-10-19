#ifndef PIGEON_FLOW_KEY_H
#define PIGEON_FLOW_KEY_H

#include "proto/address.h"

#include <string.h>

#define FLOW_APP_LEN 256

/* Conversation identity. Both addresses must have the same family. */
struct flow_key {
    struct ip_addr us_ip;
    struct ip_addr remote_ip;
    uint16_t remote_port;       /* host byte order */
    uint8_t protocol;
    char application[FLOW_APP_LEN]; /* executable basename; empty means unresolved */
};

static inline int flow_key_equal(const struct flow_key *a, const struct flow_key *b) {
    return ip_addr_equal(&a->us_ip, &b->us_ip) &&
           ip_addr_equal(&a->remote_ip, &b->remote_ip) &&
           a->remote_port == b->remote_port && a->protocol == b->protocol &&
           strncmp(a->application, b->application, FLOW_APP_LEN) == 0;
}

/* FNV-1a over family, address bytes, port, protocol and application; excludes padding. */
static inline uint32_t flow_key_hash(const struct flow_key *key) {
    uint32_t hash = ip_addr_hash(&key->us_ip);

    for (size_t i = 0; i < ip_addr_size(&key->remote_ip); i++) {
        hash = (hash ^ key->remote_ip.bytes[i]) * UINT32_C(16777619);
    }

    hash = (hash ^ (uint8_t)(key->remote_port >> 8)) * UINT32_C(16777619);
    hash = (hash ^ (uint8_t)key->remote_port) * UINT32_C(16777619);

    hash = (hash ^ key->protocol) * UINT32_C(16777619);

    for (size_t i = 0; i < sizeof key->application && key->application[i] != '\0'; i++) {
        hash = (hash ^ (uint8_t)key->application[i]) * UINT32_C(16777619);
    }

    return hash;
}

#endif
