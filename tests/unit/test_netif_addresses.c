#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <string.h>

#include "../t.h"
#include "net/netif.h"

static struct ifaddrs entries[4];
static struct sockaddr_in v4;
static struct sockaddr_in6 v6[2];
static unsigned frees;

int __wrap_getifaddrs(struct ifaddrs **out) {
    *out = entries;

    return 0;
}

void __wrap_freeifaddrs(struct ifaddrs *addresses) {
    CHECK(addresses == entries);

    frees++;
}

int __wrap_socket(int domain, int type, int protocol) {
    (void)protocol;

    if (domain == AF_NETLINK) {
        errno = ENETUNREACH;

        return -1;
    }

    CHECK(domain == AF_INET6);
    CHECK((type & SOCK_DGRAM) != 0);

    return 1234;
}

int __wrap_connect(int fd, const struct sockaddr *address, socklen_t length) {
    CHECK(fd == 1234);
    CHECK(address->sa_family == AF_INET6);
    CHECK(length == sizeof(struct sockaddr_in6));

    return 0;
}

int __wrap_getsockname(int fd, struct sockaddr *address, socklen_t *length) {
    CHECK(fd == 1234);
    CHECK(*length >= sizeof v6[0]);

    memcpy(address, &v6[0], sizeof v6[0]);
    *length = sizeof v6[0];

    return 0;
}

int __wrap_close(int fd) {
    CHECK(fd == 1234);

    return 0;
}

int main(void) {
    v4.sin_family = AF_INET;
    v6[0].sin6_family = v6[1].sin6_family = AF_INET6;

    CHECK(inet_pton(AF_INET, "192.0.2.10", &v4.sin_addr) == 1);
    CHECK(inet_pton(AF_INET6, "2001:db8::10", &v6[0].sin6_addr) == 1);
    CHECK(inet_pton(AF_INET6, "fe80::10", &v6[1].sin6_addr) == 1);

    entries[0].ifa_addr = (struct sockaddr *)&v4;
    entries[1].ifa_addr = (struct sockaddr *)&v6[0];
    entries[2].ifa_addr = (struct sockaddr *)&v6[1];

    for (size_t i = 0; i < 4; i++) {
        entries[i].ifa_name = "fake0";
        entries[i].ifa_next = i == 3 ? NULL : &entries[i + 1];
    }

    size_t count;
    struct ip_addr addresses[3];
    unsigned char before[sizeof addresses];

    memset(addresses, 0xAB, sizeof addresses);
    memcpy(before, addresses, sizeof addresses);

    CHECK(netif_addresses("fake0", NULL, 0, &count) == 0);
    CHECK(count == 3);
    CHECK(netif_addresses("fake0", addresses, 2, &count) == -1);
    CHECK(errno == ENOSPC);
    CHECK(memcmp(before, addresses, sizeof addresses) == 0);
    CHECK(netif_addresses("fake0", addresses, 3, &count) == 0);
    CHECK(count == 3);
    CHECK(addresses[0].family == 4);
    CHECK(addresses[1].family == 6);
    CHECK(addresses[2].family == 6);
    CHECK(memcmp(addresses[1].bytes, &v6[0].sin6_addr, 16) == 0);
    CHECK(memcmp(addresses[2].bytes, &v6[1].sin6_addr, 16) == 0);
    CHECK(netif_addresses("missing", addresses, 3, &count) == -1);
    CHECK(errno == EADDRNOTAVAIL);
    CHECK(frees == 4);

    struct netif_info info;

    entries[0].ifa_addr = NULL;

    CHECK(netif_select(NULL, &info) == 0);
    CHECK(strcmp(info.name, "fake0") == 0);
    CHECK(info.local_ip == 0);
    CHECK(frees == 5);

    return 0;
}
