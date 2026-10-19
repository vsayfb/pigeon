#ifndef PIGEON_NET_NETIF_H
#define PIGEON_NET_NETIF_H

#include <stdint.h>

#define NETIF_NAME_LEN 16

struct netif_info {
    char name[NETIF_NAME_LEN];
    uint32_t local_ip;          /* host byte order */
    uint32_t gateway;           /* host byte order; zero for a direct route */
};

/*
 * Looks up the IPv4 route to destination (host byte order), including
 * its interface, selected source address and optional gateway. Sends no
 * packets to destination. The result owns its name and contains no pointers.
 *
 * Returns 0 on success. Returns -1, leaving out untouched and setting errno,
 * if the route cannot be obtained or lacks an interface or source address.
 * Unsupported platforms return -1 with errno set to ENOSYS.
 */
int netif_lookup(uint32_t destination, struct netif_info *out);

/*
 * Looks up a route constrained to interface name. A NULL name allows the
 * kernel to select the interface. Ownership and return values are the same
 * as netif_lookup(); an invalid interface name also returns -1 with errno set.
 */
int netif_lookup_on(uint32_t destination, const char *name, struct netif_info *out);

#endif
