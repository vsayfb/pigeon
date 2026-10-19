#include "proto/ipv6.h"

#include <string.h>

#include "proto/bytes.h"

int ipv6_parse(const uint8_t *data, size_t len, struct ipv6_view *out) {
    if (len < IPV6_HEADER_LEN || data[0] >> 4 != 6) {
        return -1;
    }

    struct ipv6_view ip = { .src.family = 6, .dst.family = 6 };

    memcpy(ip.src.bytes, data + 8, 16);
    memcpy(ip.dst.bytes, data + 24, 16);

    ip.total_len = IPV6_HEADER_LEN + (uint32_t)be16(data + 4);
    ip.protocol = data[6];
    ip.header_len = IPV6_HEADER_LEN;

    const size_t end = len < ip.total_len ? len : ip.total_len;
    unsigned extensions = 0;
    int fragment_seen = 0;

    while (ip.protocol == 0 || ip.protocol == 43 || ip.protocol == 60 ||
           ip.protocol == 44 || ip.protocol == 51) {
        if (extensions++ == IPV6_MAX_EXTENSIONS || end - ip.header_len < 2) {
            return -1;
        }

        const uint8_t *header = data + ip.header_len;
        size_t size = ((size_t)header[1] + 1) * 8;

        if (ip.protocol == 44) {
            if (fragment_seen || end - ip.header_len < 8) {
                return -1;
            }

            fragment_seen = 1;
            size = 8;
            ip.frag_offset = be16(header + 2) & 0xFFF8;
        } else if (ip.protocol == 51) {
            size = ((size_t)header[1] + 2) * 4;

            if (size < 12) {
                return -1;
            }
        }

        if (size > end - ip.header_len) {
            return -1;
        }

        ip.protocol = header[0];
        ip.header_len += size;

        if (ip.frag_offset != 0) {
            break;
        }
    }

    ip.payload = data + ip.header_len;
    ip.payload_len = end - ip.header_len;
    ip.payload_wire_len = ip.total_len - ip.header_len;
    *out = ip;

    return 0;
}
