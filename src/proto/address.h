#ifndef PIGEON_PROTO_ADDRESS_H
#define PIGEON_PROTO_ADDRESS_H

#include <stddef.h>
#include <stdint.h>

#define IP_ADDR_STR_LEN 46

/* family is 4 or 6. bytes holds 4 or 16 network-order address bytes.
 * IPv4 and IPv4-mapped IPv6 addresses remain distinct identities. */
struct ip_addr {
    uint8_t family;
    uint8_t bytes[16];
};

/* Constructs an IPv4 address from a host-order integer. */
struct ip_addr ip_addr_v4(uint32_t value);

/* Returns an IPv4 host-order integer, or zero for a non-IPv4 address. */
uint32_t ip_addr_v4_value(const struct ip_addr *address);

/* Parses numeric IPv4/IPv6 text. Returns 0 on success or -1, leaving out
 * untouched, for invalid text. Interface-zone suffixes are not accepted. */
int ip_addr_parse(const char *text, struct ip_addr *out);

/* Formats a numeric address into buf, returning buf. Invalid families
 * produce an empty string. buf provides IP_ADDR_STR_LEN bytes. */
const char *ip_addr_str(const struct ip_addr *address, char buf[IP_ADDR_STR_LEN]);

size_t ip_addr_size(const struct ip_addr *address);
int ip_addr_equal(const struct ip_addr *a, const struct ip_addr *b);
uint32_t ip_addr_hash(const struct ip_addr *address);

/* Presentation classification only: does not prove that a peer is on the
 * selected interface's subnet. Mapped IPv6 is classified by its IPv4 address
 * without changing address identity. Public/unspecified/reserved addresses
 * and globally scoped multicast receive no Local network label. */
enum ip_scope {
    IP_SCOPE_NONE,
    IP_SCOPE_PRIVATE,
    IP_SCOPE_LINK_LOCAL,
    IP_SCOPE_LOOPBACK,
    IP_SCOPE_LOCAL_MULTICAST,
    IP_SCOPE_BROADCAST
};

enum ip_scope ip_addr_scope(const struct ip_addr *address);
const char *ip_scope_description(enum ip_scope scope);
const char *ip_scope_label(enum ip_scope scope);

#endif
