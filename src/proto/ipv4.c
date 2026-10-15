#include "proto/ipv4.h"

#include <arpa/inet.h>

#include "proto/bytes.h"

int ipv4_parse(const uint8_t *data, const size_t len, struct ipv4_view *out) {
    if (len < IPV4_MIN_HEADER_LEN) {
        return -1;
    }

    /* Byte 0 packs two 4-bit fields: version in the high half, IHL in the low. */
    const unsigned version = data[0] >> 4;
    const size_t header_len = (size_t)(data[0] & 0x0F) * 4;

    if (version != 4) {
        return -1;
    }

    if (header_len < IPV4_MIN_HEADER_LEN || header_len > len) {
        return -1;
    }

    const uint16_t total_len = be16(data + 2);

    if (total_len < header_len) {
        return -1;
    }

    /* Trust neither number alone: stop at whichever ends first. */
    const size_t end = total_len < len ? total_len : len;

    out->header_len = (uint8_t)header_len;
    out->protocol = data[9];
    out->total_len = total_len;
    out->src = be32(data + 12);
    out->dst = be32(data + 16);
    out->payload = data + header_len;
    out->payload_len = end - header_len;

    return 0;
}

const char *ipv4_addr_str(const uint32_t addr, char buf[IPV4_STR_LEN]) {
    const uint32_t net = htonl(addr);

    if (inet_ntop(AF_INET, &net, buf, IPV4_STR_LEN) == NULL) {
        buf[0] = '\0';
    }

    return buf;
}
