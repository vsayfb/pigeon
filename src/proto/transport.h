#ifndef PIGEON_PROTO_TRANSPORT_H
#define PIGEON_PROTO_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "proto/ipv4.h"
#include "proto/ipv6.h"

#define TCP_MIN_HEADER_LEN 20
#define UDP_HEADER_LEN     8

/*
 * Decoded TCP header and the bytes that follow it.
 *
 * `payload_len` is the number of payload bytes readable at `payload`.
 * `payload_wire_len` is the payload size on the wire according to the IP
 * header; it exceeds `payload_len` when the capture was truncated.
 */
struct tcp_view {
    uint16_t src_port;          /* host byte order */
    uint16_t dst_port;
    uint8_t header_len;         /* in bytes: data offset * 4, 20 to 60 */
    const uint8_t *payload;     /* points into the buffer behind the ipv4_view */
    size_t payload_len;
    size_t payload_wire_len;
};

/* Decoded UDP header and the bytes that follow it. Payload lengths have the
 * same meaning as in struct tcp_view. */
struct udp_view {
    uint16_t src_port;
    uint16_t dst_port;
    const uint8_t *payload;
    size_t payload_len;
    size_t payload_wire_len;
};

/*
 * Decodes the TCP header at the start of `ip->payload` into `out`. `ip` must
 * come from ipv4_parse(). `out->payload` points into the buffer behind `ip`.
 *
 * Payload sizes derive from the IP header, not from the captured length, so
 * Ethernet padding is never counted: `payload_wire_len` is
 * `ip->total_len - ip->header_len - header_len`.
 *
 * Returns 0 on success. Returns -1, leaving `out` untouched, if `ip` is a
 * later fragment, the TCP header is not fully captured, or its data offset is
 * below 5.
 */
int tcp_parse(const struct ipv4_view *ip, struct tcp_view *out);

/*
 * Decodes the UDP header at the start of `ip->payload` into `out`. Same
 * preconditions and length semantics as tcp_parse().
 *
 * When the UDP length field and the IP payload size disagree, the smaller
 * one bounds the datagram. A UDP length below the IP size leaves trailing
 * bytes, which are ignored; a UDP length above it occurs in first fragments,
 * where the rest of the datagram is in later packets.
 *
 * Returns 0 on success. Returns -1, leaving `out` untouched, if `ip` is a
 * later fragment, fewer than UDP_HEADER_LEN bytes were captured, or the UDP
 * length is below UDP_HEADER_LEN.
 */
int udp_parse(const struct ipv4_view *ip, struct udp_view *out);

/* Same ownership, payload semantics and return values as the IPv4 parsers.
 * Input must come from ipv6_parse(); later fragments are rejected. */
int tcp_parse_ipv6(const struct ipv6_view *ip, struct tcp_view *out);
int udp_parse_ipv6(const struct ipv6_view *ip, struct udp_view *out);

#endif
