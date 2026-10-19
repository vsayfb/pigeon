#include "proto/icmp.h"

int icmp_parse(const uint8_t *data, size_t captured, size_t wire, int ipv6,
               struct icmp_view *out) {
    if (captured < 4 || wire < 4) {
        return -1;
    }

    const uint8_t type = data[0];
    const uint8_t header = !ipv6 || (type >= 1 && type <= 4) || type == 128 || type == 129 ? 8 : 4;

    if (captured < header || wire < header) {
        return -1;
    }

    const size_t end = captured < wire ? captured : wire;
    const struct icmp_view message = {
        .type = type,
        .code = data[1],
        .header_len = header,
        .payload = data + header,
        .payload_len = end - header,
        .payload_wire_len = wire - header
    };

    *out = message;

    return 0;
}
