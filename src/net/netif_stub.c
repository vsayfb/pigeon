#include "net/netif.h"

#include <errno.h>

int netif_lookup_on(uint32_t destination, const char *name, struct netif_info *out) {
    (void)destination;
    (void)name;
    (void)out;

    errno = ENOSYS;

    return -1;
}

int netif_lookup(uint32_t destination, struct netif_info *out) {
    return netif_lookup_on(destination, 0, out);
}
