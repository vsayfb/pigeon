#include <arpa/inet.h>
#include <errno.h>
#include <linux/rtnetlink.h>
#include <string.h>

#include "../t.h"
#include "net/netif.h"
#include "net/netif_linux.h"
#include "proto/ipv4.h"

struct reply {
    struct nlmsghdr header;
    struct rtmsg message;

    struct {
        struct rtattr header;
        uint32_t value;
    } attributes[3];
};

static struct reply make_reply(void) {
    struct reply reply = { 0 };

    reply.header.nlmsg_len = sizeof reply;
    reply.header.nlmsg_type = RTM_NEWROUTE;
    reply.message.rtm_family = AF_INET;
    reply.message.rtm_type = RTN_UNICAST;
    reply.attributes[0].header.rta_type = RTA_OIF;
    reply.attributes[0].value = 3;
    reply.attributes[1].header.rta_type = RTA_PREFSRC;
    reply.attributes[1].value = htonl(0xC000020A);
    reply.attributes[2].header.rta_type = RTA_GATEWAY;
    reply.attributes[2].value = htonl(0xC0000201);

    for (unsigned i = 0; i < 3; i++) {
        reply.attributes[i].header.rta_len = RTA_LENGTH(sizeof(uint32_t));
    }

    return reply;
}

static void check_failure(const void *data, size_t len, int expected_errno) {
    struct netif_route route;
    unsigned char before[sizeof route];

    memset(&route, 0xAB, sizeof route);
    memcpy(before, &route, sizeof route);

    CHECK(netif_route_decode(data, len, &route) == -1);
    CHECK(errno == expected_errno);
    CHECK(memcmp(before, &route, sizeof route) == 0);
}

static void test_decode(void) {
    struct reply reply = make_reply();
    struct netif_route route;

    CHECK(netif_route_decode(&reply, sizeof reply, &route) == 0);
    CHECK(route.index == 3);
    CHECK(route.local_ip == 0xC000020A);
    CHECK(route.gateway == 0xC0000201);

    for (size_t len = 0; len < sizeof reply; len++) {
        check_failure(&reply, len, EPROTO);
    }

    reply.header.nlmsg_len -= sizeof reply.attributes[2];

    CHECK(netif_route_decode(&reply, sizeof reply, &route) == 0);
    CHECK(route.gateway == 0);

    reply = make_reply();
    reply.attributes[1].header.rta_type = RTA_UNSPEC;
    check_failure(&reply, sizeof reply, ENETUNREACH);

    reply = make_reply();
    reply.attributes[0].value = 0;
    check_failure(&reply, sizeof reply, ENETUNREACH);

    reply = make_reply();
    reply.attributes[2].header.rta_len = 0;
    check_failure(&reply, sizeof reply, EPROTO);

    reply = make_reply();
    reply.attributes[2].header.rta_len = 100;
    check_failure(&reply, sizeof reply, EPROTO);

    reply = make_reply();
    reply.attributes[1].header.rta_len = RTA_LENGTH(1);
    check_failure(&reply, sizeof reply, EPROTO);

    reply = make_reply();
    reply.message.rtm_type = RTN_UNREACHABLE;
    check_failure(&reply, sizeof reply, ENETUNREACH);

    struct {
        struct nlmsghdr header;
        struct nlmsgerr error;
    } failure = { 0 };
    failure.header.nlmsg_len = sizeof failure;
    failure.header.nlmsg_type = NLMSG_ERROR;
    failure.error.error = -ENETUNREACH;
    check_failure(&failure, sizeof failure, ENETUNREACH);
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--live") == 0) {
        struct netif_info info;
        char local[IPV4_STR_LEN];
        char gateway[IPV4_STR_LEN];

        if (netif_lookup_on(0x01010101, argc == 3 ? argv[2] : NULL, &info) == -1) {
            perror("netif_lookup");

            return 1;
        }

        printf("interface=%s local=%s gateway=%s\n", info.name,
               ipv4_addr_str(info.local_ip, local),
               ipv4_addr_str(info.gateway, gateway));

        return 0;
    }

    struct netif_info info;
    unsigned char before[sizeof info];

    memset(&info, 0xAB, sizeof info);
    memcpy(before, &info, sizeof info);

    CHECK(netif_lookup_on(0x01010101, "pigeon-missing-interface", &info) == -1);
    CHECK(memcmp(before, &info, sizeof info) == 0);

    test_decode();
    puts("netif: ok");

    return 0;
}
