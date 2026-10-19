#ifndef PIGEON_PROTO_PACKET_H
#define PIGEON_PROTO_PACKET_H

#include "proto/ethernet.h"
#include "proto/transport.h"

enum packet_kind {
    PACKET_ETHERNET,
    PACKET_IPV4,
    PACKET_TCP,
    PACKET_UDP
};

/* kind identifies the deepest decoded header; only that layer and its
 * enclosing layers are valid. Payload pointers borrow the input frame. */
struct packet_view {
    enum packet_kind kind;
    struct eth_view eth;
    struct ipv4_view ip;
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

#endif
