#include "proto/address.h"

#include <arpa/inet.h>
#include <string.h>
#include "proto/bytes.h"

struct ip_addr ip_addr_v4(uint32_t value) {
    const struct ip_addr address = {
        .family = 4,
        .bytes = { (uint8_t)(value >> 24), (uint8_t)(value >> 16),
                   (uint8_t)(value >> 8), (uint8_t)value }
    };

    return address;
}

size_t ip_addr_size(const struct ip_addr *address) {
    return address->family == 4 ? 4 : address->family == 6 ? 16 : 0;
}

int ip_addr_parse(const char *text, struct ip_addr *out) {
    struct ip_addr address = { .family = 4 };

    if (inet_pton(AF_INET, text, address.bytes) != 1) {
        address.family = 6;

        if (inet_pton(AF_INET6, text, address.bytes) != 1) {
            return -1;
        }
    }

    *out = address;

    return 0;
}

const char *ip_addr_str(const struct ip_addr *address, char buf[IP_ADDR_STR_LEN]) {
    const int family = address->family == 4 ? AF_INET : AF_INET6;

    if (ip_addr_size(address) == 0 ||
        inet_ntop(family, address->bytes, buf, IP_ADDR_STR_LEN) == NULL) {
        buf[0] = '\0';
    }

    return buf;
}

int ip_addr_equal(const struct ip_addr *a, const struct ip_addr *b) {
    const size_t size = ip_addr_size(a);

    return size != 0 && a->family == b->family && memcmp(a->bytes, b->bytes, size) == 0;
}

uint32_t ip_addr_hash(const struct ip_addr *address) {
    uint32_t hash = UINT32_C(2166136261);

    hash = (hash ^ address->family) * UINT32_C(16777619);

    for (size_t i = 0; i < ip_addr_size(address); i++) {
        hash = (hash ^ address->bytes[i]) * UINT32_C(16777619);
    }

    return hash;
}

uint32_t ip_addr_v4_value(const struct ip_addr *address) {
    return address->family == 4 ? be32(address->bytes) : 0;
}
