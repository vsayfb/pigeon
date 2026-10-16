#include "proto/transport.h"

#include "proto/bytes.h"

/*
 * Size of the IP payload according to the IP header. Independent of the
 * captured length and of Ethernet padding.
 */
static size_t ip_payload_wire_len(const struct ipv4_view *ip) {
    return (size_t)(ip->total_len - ip->header_len);
}

int tcp_parse(const struct ipv4_view *ip, struct tcp_view *out) {
    if (ip->frag_offset != 0) {
        return -1;
    }

    const uint8_t *seg = ip->payload;
    const size_t captured = ip->payload_len;

    if (captured < TCP_MIN_HEADER_LEN) {
        return -1;
    }

    /* Byte 12: data offset in the high 4 bits, counted in 4-byte words. */
    const size_t header_len = (size_t)(seg[12] >> 4) * 4;

    if (header_len < TCP_MIN_HEADER_LEN || header_len > captured) {
        return -1;
    }

    /* ipv4_parse guarantees captured <= ip_payload_wire_len(ip), and
     * header_len <= captured, so neither subtraction can underflow. */
    out->src_port = be16(seg);
    out->dst_port = be16(seg + 2);
    out->header_len = (uint8_t)header_len;
    out->payload = seg + header_len;
    out->payload_len = captured - header_len;
    out->payload_wire_len = ip_payload_wire_len(ip) - header_len;

    return 0;
}

int udp_parse(const struct ipv4_view *ip, struct udp_view *out) {
    if (ip->frag_offset != 0) {
        return -1;
    }

    const uint8_t *dgram = ip->payload;
    const size_t captured = ip->payload_len;

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
    const size_t wire = ip_payload_wire_len(ip);
    const size_t wire_end = udp_len < wire ? udp_len : wire;
    const size_t read_end = wire_end < captured ? wire_end : captured;

    out->src_port = be16(dgram);
    out->dst_port = be16(dgram + 2);
    out->payload = dgram + UDP_HEADER_LEN;
    out->payload_len = read_end - UDP_HEADER_LEN;
    out->payload_wire_len = wire_end - UDP_HEADER_LEN;

    return 0;
}
