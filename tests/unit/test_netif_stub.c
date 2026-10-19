#include <errno.h>
#include <string.h>

#include "../t.h"
#include "net/netif.h"

int main(void) {
    struct netif_info info;
    unsigned char before[sizeof info];

    memset(&info, 0xAB, sizeof info);
    memcpy(before, &info, sizeof info);

    CHECK(netif_lookup(0x01010101, &info) == -1);
    CHECK(errno == ENOSYS);
    CHECK(memcmp(before, &info, sizeof info) == 0);

    CHECK(netif_lookup_on(0x01010101, "eth0", &info) == -1);
    CHECK(errno == ENOSYS);
    CHECK(memcmp(before, &info, sizeof info) == 0);

    return 0;
}
