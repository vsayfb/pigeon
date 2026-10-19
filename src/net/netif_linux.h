#ifndef PIGEON_NET_NETIF_LINUX_H
#define PIGEON_NET_NETIF_LINUX_H

#include <stddef.h>
#include <stdint.h>

/* Internal decoded RTM_NEWROUTE attributes, in host byte order. */
struct netif_route {
    unsigned index;
    uint32_t local_ip;
    uint32_t gateway;
};

/* Decodes one netlink reply. Returns 0 on success, or -1 with errno set
 * and out untouched for a malformed, unsuccessful or incomplete reply. */
int netif_route_decode(const void *data, size_t len, struct netif_route *out);

#endif
