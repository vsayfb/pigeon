#ifndef PIGEON_PROTO_PACKET_H
#define PIGEON_PROTO_PACKET_H

#include "proto/ethernet.h"
#include "proto/transport.h"

enum packet_kind {
    PACKET_ETHERNET,
    PACKET_IPV4,
    PACKET_IPV6,
    PACKET_TCP,
    PACKET_UDP
};

/* kind identifies the deepest decoded header; only that layer and its
 * enclosing layers are valid. Payload pointers borrow the input frame. */
struct packet_view {
    enum packet_kind kind;
    struct eth_view eth;
    struct ipv4_view ip;
    struct ipv6_view ip6;
    union {
        struct tcp_view tcp;
        struct udp_view udp;
    } transport;
};

/*
 * Decodes an Ethernet II frame with `len` readable bytes into `out`.
 * Payload pointers remain valid only while the input frame is valid.
 * Unsupported EtherTypes, IP protocols and later fragments succeed with
 * only their enclosing headers decoded. Fragments are not reassembled.
 *
 * Returns 0 on success. Returns -1, leaving `out` untouched, if a supported
 * header is malformed or not fully captured.
 */
int packet_parse(const uint8_t *frame, size_t len, struct packet_view *out);

/* Returns the source/destination address and final IP protocol of a decoded
 * IP packet. IPv4 fields remain in ip; IPv6 fields remain in ip6. */
struct ip_addr packet_source(const struct packet_view *packet);
struct ip_addr packet_destination(const struct packet_view *packet);
uint8_t packet_protocol(const struct packet_view *packet);

#endif
