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

enum ip_scope ip_addr_scope(const struct ip_addr *address) {
    if (address->family == 4) {
        const uint8_t *b = address->bytes;

        if (b[0] == 10 || (b[0] == 172 && (b[1] & 0xf0) == 16) ||
            (b[0] == 192 && b[1] == 168)) {
            return IP_SCOPE_PRIVATE;
        }

        if (b[0] == 127) {
            return IP_SCOPE_LOOPBACK;
        }

        if (b[0] == 169 && b[1] == 254) {
            return IP_SCOPE_LINK_LOCAL;
        }

        if ((b[0] == 224 && b[1] == 0 && b[2] == 0) || b[0] == 239) {
            return IP_SCOPE_LOCAL_MULTICAST;
        }

        return ip_addr_v4_value(address) == UINT32_MAX ? IP_SCOPE_BROADCAST : IP_SCOPE_NONE;
    }

    if (address->family != 6) {
        return IP_SCOPE_NONE;
    }

    const uint8_t *b = address->bytes;
    static const uint8_t loopback[16] = { [15] = 1 };
    static const uint8_t mapped[12] = { [10] = 255, [11] = 255 };

    if (memcmp(b, mapped, sizeof mapped) == 0) {
        const struct ip_addr v4 = ip_addr_v4(be32(b + 12));

        return ip_addr_scope(&v4);
    }

    if (memcmp(b, loopback, sizeof loopback) == 0) {
        return IP_SCOPE_LOOPBACK;
    }

    if ((b[0] & 0xfe) == 0xfc) {
        return IP_SCOPE_PRIVATE;
    }

    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) {
        return IP_SCOPE_LINK_LOCAL;
    }

    const unsigned scope = b[1] & 0x0f;

    if (b[0] == 0xff && (scope == 1 || scope == 2 || scope == 3 || scope == 4 || scope == 5 || scope == 8)) {
        return IP_SCOPE_LOCAL_MULTICAST;
    }

    return IP_SCOPE_NONE;
}

const char *ip_scope_description(enum ip_scope scope) {
    switch (scope) {
        case IP_SCOPE_PRIVATE: return "Private address range (may include VPN networks)";
        case IP_SCOPE_LINK_LOCAL: return "Link-local address range";
        case IP_SCOPE_LOOPBACK: return "Loopback address (this device)";
        case IP_SCOPE_LOCAL_MULTICAST: return "Locally scoped multicast address";
        case IP_SCOPE_BROADCAST: return "Local broadcast address";
        default: return "";
    }
}

const char *ip_scope_label(enum ip_scope scope) {
    return scope == IP_SCOPE_LOOPBACK ? "This device" : scope != IP_SCOPE_NONE ? "Local network" : "";
}
