#include <string.h>

#include "../t.h"
#include "proto/address.h"

int main(void) {
    const struct { const char *ip; enum ip_scope scope; } cases[] = {
        {"10.0.0.1", IP_SCOPE_PRIVATE}, {"172.16.0.1", IP_SCOPE_PRIVATE},
        {"172.31.255.255", IP_SCOPE_PRIVATE}, {"192.168.1.1", IP_SCOPE_PRIVATE},
        {"127.0.0.1", IP_SCOPE_LOOPBACK}, {"127.255.255.255", IP_SCOPE_LOOPBACK},
        {"169.254.1.1", IP_SCOPE_LINK_LOCAL}, {"224.0.0.251", IP_SCOPE_LOCAL_MULTICAST},
        {"239.255.255.250", IP_SCOPE_LOCAL_MULTICAST}, {"255.255.255.255", IP_SCOPE_BROADCAST},
        {"::1", IP_SCOPE_LOOPBACK}, {"fc00::1", IP_SCOPE_PRIVATE}, {"fdff::1", IP_SCOPE_PRIVATE},
        {"fe80::1", IP_SCOPE_LINK_LOCAL}, {"febf::1", IP_SCOPE_LINK_LOCAL},
        {"ff02::fb", IP_SCOPE_LOCAL_MULTICAST}, {"ff05::1", IP_SCOPE_LOCAL_MULTICAST},
        {"ff18::1", IP_SCOPE_LOCAL_MULTICAST}, {"::ffff:192.168.1.1", IP_SCOPE_PRIVATE},
        {"::ffff:127.0.0.1", IP_SCOPE_LOOPBACK},
        {"0.0.0.0", IP_SCOPE_NONE}, {"8.8.8.8", IP_SCOPE_NONE}, {"100.64.0.1", IP_SCOPE_NONE},
        {"172.15.255.255", IP_SCOPE_NONE}, {"172.32.0.0", IP_SCOPE_NONE}, {"192.169.0.1", IP_SCOPE_NONE},
        {"224.0.1.1", IP_SCOPE_NONE}, {"238.255.255.255", IP_SCOPE_NONE}, {"240.0.0.1", IP_SCOPE_NONE},
        {"192.0.2.1", IP_SCOPE_NONE}, {"::", IP_SCOPE_NONE}, {"2001:db8::1", IP_SCOPE_NONE},
        {"2001:4860::8888", IP_SCOPE_NONE}, {"fe7f::1", IP_SCOPE_NONE}, {"fec0::1", IP_SCOPE_NONE},
        {"ff0e::1", IP_SCOPE_NONE}, {"ff00::1", IP_SCOPE_NONE}, {"::ffff:8.8.8.8", IP_SCOPE_NONE}
    };

    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct ip_addr address;

        CHECK(ip_addr_parse(cases[i].ip, &address) == 0);

        const struct ip_addr original = address;

        CHECK(ip_addr_scope(&address) == cases[i].scope);
        CHECK(memcmp(&original, &address, sizeof address) == 0);
        CHECK((ip_scope_description(cases[i].scope)[0] != '\0') == (cases[i].scope != IP_SCOPE_NONE));
    }

    const struct ip_addr invalid = { 0 };

    CHECK(ip_addr_scope(&invalid) == IP_SCOPE_NONE);
    CHECK(strcmp(ip_scope_label(IP_SCOPE_LOOPBACK), "This device") == 0);
    CHECK(strcmp(ip_scope_label(IP_SCOPE_PRIVATE), "Local network") == 0);
    CHECK(ip_scope_label(IP_SCOPE_NONE)[0] == '\0');

    return 0;
}
