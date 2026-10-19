#include "proto/quic.h"

#include <string.h>

#include "proto/bytes.h"

static int integer(const uint8_t *data, size_t len, size_t *offset, uint64_t *value) {
    if (*offset >= len) {
        return 0;
    }

    const size_t bytes = (size_t)1 << (data[*offset] >> 6);

    if (bytes > len - *offset) {
        return 0;
    }

    uint64_t result = data[*offset] & 0x3f;

    for (size_t i = 1; i < bytes; i++) {
        result = (result << 8) | data[*offset + i];
    }

    *offset += bytes;
    *value = result;

    return 1;
}

int quic_parse_long(const uint8_t *data, size_t captured, struct quic_header *out) {
    if (captured < 7 || (data[0] & 0xc0) != 0xc0) {
        return 0;
    }

    struct quic_header header = { .version = be32(data + 1) };
    const unsigned type = (data[0] >> 4) & 3;
    const int v2 = header.version == UINT32_C(0x6b3343cf);

    if (header.version != 1 && !v2) {
        return 0;
    }

    header.initial = type == (v2 ? 1u : 0u);

    if (!header.initial && type != (v2 ? 3u : 2u)) {
        return 0;
    }

    size_t offset = 6;

    header.dcid_len = data[5];

    if (header.dcid_len > QUIC_CID_MAX || header.dcid_len >= captured - offset) {
        return 0;
    }

    memcpy(header.dcid, data + offset, header.dcid_len);
    offset += header.dcid_len;
    header.scid_len = data[offset++];

    if (header.scid_len > QUIC_CID_MAX || header.scid_len > captured - offset) {
        return 0;
    }

    memcpy(header.scid, data + offset, header.scid_len);
    offset += header.scid_len;

    uint64_t length;

    if (header.initial) {
        if (!integer(data, captured, &offset, &length) || length > captured - offset) {
            return 0;
        }

        offset += (size_t)length;
    }

    /* Length includes the protected packet number and encrypted payload.
     * Header protection needs a 16-byte sample beginning four bytes after
     * the packet-number offset, so fewer than 20 bytes cannot be valid. */
    if (!integer(data, captured, &offset, &length) || length < 20 || length > captured - offset) {
        return 0;
    }

    *out = header;

    return 1;
}

int quic_observe(struct quic_probe *probe, const uint8_t *data, size_t captured,
                  size_t wire, uint16_t local_port, int outgoing, int64_t now) {
    struct quic_header header;

    if (captured > wire || !quic_parse_long(data, captured, &header)) {
        return 0;
    }

    const int recent = probe->active && now >= probe->seen &&
                       (uint64_t)now - (uint64_t)probe->seen <= 30;

    if (recent && probe->local_port == local_port && probe->outgoing != outgoing &&
        probe->version == header.version && probe->scid_len == header.dcid_len &&
        memcmp(probe->scid, header.dcid, header.dcid_len) == 0) {
        return 1;
    }

    if (header.initial && captured == wire && wire >= 1200 && header.scid_len >= 8) {
        probe->version = header.version;
        probe->scid_len = header.scid_len;
        memcpy(probe->scid, header.scid, header.scid_len);
        probe->local_port = local_port;
        probe->outgoing = outgoing;
        probe->seen = now;
        probe->active = 1;
    }

    return 0;
}
