#ifndef PIGEON_PROTO_PROTOCOL_H
#define PIGEON_PROTO_PROTOCOL_H

#include <stdint.h>

#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17
#define IP_PROTO_ICMPV6 58
#define IP_PROTO_ESP    50

static inline int protocol_has_ports(uint8_t protocol) {
    return protocol == IP_PROTO_TCP || protocol == IP_PROTO_UDP;
}

static inline const char *protocol_label(uint8_t protocol) {
    switch (protocol) {
        case IP_PROTO_ICMP: return "icmp";
        case IP_PROTO_TCP: return "tcp";
        case IP_PROTO_UDP: return "udp";
        case IP_PROTO_ICMPV6: return "icmpv6";
        case IP_PROTO_ESP: return "esp";
        default: return "other";
    }
}

static inline const char *protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IP_PROTO_ICMP: return "ICMP";
        case IP_PROTO_TCP: return "TCP";
        case IP_PROTO_UDP: return "UDP";
        case IP_PROTO_ICMPV6: return "ICMPv6";
        case IP_PROTO_ESP: return "ESP";
        default: return "other";
    }
}

#endif
