#include "proto/transport.h"

#include "proto/bytes.h"

static int tcp_decode(const uint8_t *seg, size_t captured, size_t wire,
                       struct tcp_view *out) {
    if (captured < TCP_MIN_HEADER_LEN) {
        return -1;
    }

    /* Byte 12: data offset in the high 4 bits, counted in 4-byte words. */
    const size_t header_len = (size_t)(seg[12] >> 4) * 4;

    if (header_len < TCP_MIN_HEADER_LEN || header_len > captured) {
        return -1;
    }

    /* IP parsing bounds captured by wire; header_len <= captured. */
    out->src_port = be16(seg);
    out->dst_port = be16(seg + 2);
    out->header_len = (uint8_t)header_len;
    out->payload = seg + header_len;
    out->payload_len = captured - header_len;
    out->payload_wire_len = wire - header_len;

    return 0;
}

static int udp_decode(const uint8_t *dgram, size_t captured, size_t wire,
                       struct udp_view *out) {
    if (captured < UDP_HEADER_LEN) {
        return -1;
    }

    const size_t udp_len = be16(dgram + 4);

    if (udp_len < UDP_HEADER_LEN) {
        return -1;
    }

    /* The datagram ends at the UDP length or the end of the IP payload,
     * whichever is smaller; readable bytes are further bounded by the
     * capture. Both bounds are at least UDP_HEADER_LEN here. */
    const size_t wire_end = udp_len < wire ? udp_len : wire;
    const size_t read_end = wire_end < captured ? wire_end : captured;

    out->src_port = be16(dgram);
    out->dst_port = be16(dgram + 2);
    out->payload = dgram + UDP_HEADER_LEN;
    out->payload_len = read_end - UDP_HEADER_LEN;
    out->payload_wire_len = wire_end - UDP_HEADER_LEN;

    return 0;
}

int tcp_parse(const struct ipv4_view *ip, struct tcp_view *out) {
    if (ip->frag_offset != 0) {
        return -1;
    }

    return tcp_decode(ip->payload, ip->payload_len, ip->total_len - ip->header_len, out);
}

int udp_parse(const struct ipv4_view *ip, struct udp_view *out) {
    if (ip->frag_offset != 0) {
        return -1;
    }

    return udp_decode(ip->payload, ip->payload_len, ip->total_len - ip->header_len, out);
}

int tcp_parse_ipv6(const struct ipv6_view *ip, struct tcp_view *out) {
    if (ip->frag_offset != 0) {
        return -1;
    }

    return tcp_decode(ip->payload, ip->payload_len, ip->payload_wire_len, out);
}

int udp_parse_ipv6(const struct ipv6_view *ip, struct udp_view *out) {
    if (ip->frag_offset != 0) {
        return -1;
    }

    return udp_decode(ip->payload, ip->payload_len, ip->payload_wire_len, out);
}
