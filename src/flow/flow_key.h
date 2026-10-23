#ifndef PIGEON_FLOW_KEY_H
#define PIGEON_FLOW_KEY_H

#include "proto/address.h"

#include <string.h>

#define FLOW_APP_LEN 256

/* Conversation identity. Both addresses must have the same family. */
struct flow_key {
    struct ip_addr us_ip;
    struct ip_addr remote_ip;
    uint16_t remote_port;       /* host byte order; zero sentinel for ICMP/ICMPv6/ESP */
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

/* Decodes the GUI identity: address length/bytes, peer length/bytes,
 * big-endian port, protocol and application, all hex encoded. */
static inline int flow_key_decode(const char *hex, struct flow_key *out) {
    unsigned char bytes[2 + 32 + 3 + FLOW_APP_LEN - 1];
    const size_t length = strlen(hex);

    if (length % 2 != 0 || length / 2 > sizeof bytes || length < 26) {
        return -1;
    }

    for (size_t i = 0; i < length; i += 2) {
        unsigned value = 0;

        for (size_t j = 0; j < 2; j++) {
            const unsigned char c = (unsigned char)hex[i + j];
            const int digit = c >= '0' && c <= '9' ? c - '0' :
                              c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                              c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

            if (digit < 0) {
                return -1;
            }

            value = value * 16 + (unsigned)digit;
        }

        bytes[i / 2] = (unsigned char)value;
    }

    const size_t size = bytes[0];
    const size_t fixed = 2 + 2 * size + 3;

    if ((size != 4 && size != 16) || length / 2 < fixed || bytes[1 + size] != size) {
        return -1;
    }

    const size_t app_length = length / 2 - fixed;
    struct flow_key key = { 0 };

    key.us_ip.family = key.remote_ip.family = size == 4 ? 4 : 6;
    memcpy(key.us_ip.bytes, bytes + 1, size);
    memcpy(key.remote_ip.bytes, bytes + size + 2, size);
    key.remote_port = (uint16_t)((bytes[2 + 2 * size] << 8) | bytes[3 + 2 * size]);
    key.protocol = bytes[4 + 2 * size];

    if (app_length >= FLOW_APP_LEN || memchr(bytes + fixed, 0, app_length) != NULL ||
        (key.protocol != 1 && key.protocol != 6 && key.protocol != 17 && key.protocol != 50 && key.protocol != 58)) {
        return -1;
    }

    memcpy(key.application, bytes + fixed, app_length);
    *out = key;

    return 0;
}

#endif
