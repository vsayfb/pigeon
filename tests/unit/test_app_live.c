#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../t.h"
#include "app/app_internal.h"

static uint16_t bound_port(int fd, int family) {
    struct sockaddr_storage address;
    socklen_t length = sizeof address;

    CHECK(getsockname(fd, (struct sockaddr *)&address, &length) == 0);

    return ntohs(family == AF_INET ? ((struct sockaddr_in *)&address)->sin_port
                                 : ((struct sockaddr_in6 *)&address)->sin6_port);
}

static void check_owner(struct app_snapshot *snapshot, struct flow_key *key, uint16_t port) {
    char application[FLOW_APP_LEN];

    app_snapshot_lookup(snapshot, key, port, application);
    CHECK(strcmp(application, "test_app_live") == 0);
}

static void test_local_sockets(int family) {
    const int tcp = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (tcp == -1 && family == AF_INET6 && errno == EAFNOSUPPORT) {
        return;
    }

    CHECK(tcp != -1);

    struct sockaddr_storage address = { 0 };
    struct sockaddr_in *v4 = (struct sockaddr_in *)&address;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;
    const socklen_t length = family == AF_INET ? sizeof *v4 : sizeof *v6;

    if (family == AF_INET) {
        v4->sin_family = AF_INET;
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        v6->sin6_family = AF_INET6;
        v6->sin6_addr = in6addr_loopback;
    }

    CHECK(bind(tcp, (struct sockaddr *)&address, length) == 0);
    CHECK(listen(tcp, 1) == 0);

    socklen_t actual = sizeof address;

    CHECK(getsockname(tcp, (struct sockaddr *)&address, &actual) == 0);

    const int client = socket(family, SOCK_STREAM | SOCK_CLOEXEC, 0);

    CHECK(client != -1);
    CHECK(connect(client, (struct sockaddr *)&address, length) == 0);

    const int accepted = accept(tcp, NULL, NULL);
    const int udp = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    const int connected_udp = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    CHECK(accepted != -1 && udp != -1 && connected_udp != -1);

    if (family == AF_INET) {
        v4->sin_port = 0;
        v4->sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        v6->sin6_port = 0;
        v6->sin6_addr = in6addr_any;
    }

    CHECK(bind(udp, (struct sockaddr *)&address, length) == 0);

    if (family == AF_INET) {
        v4->sin_port = htons(443);
        v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        v6->sin6_port = htons(443);
        v6->sin6_addr = in6addr_loopback;
    }

    CHECK(connect(connected_udp, (struct sockaddr *)&address, length) == 0);

    struct app_snapshot *snapshot = app_snapshot_read();
    struct flow_key key = { .protocol = 6, .remote_port = bound_port(tcp, family) };

    CHECK(snapshot != NULL);
    app_snapshot_sort(snapshot);
    CHECK(ip_addr_parse(family == AF_INET ? "127.0.0.1" : "::1", &key.us_ip) == 0);
    key.remote_ip = key.us_ip;
    check_owner(snapshot, &key, bound_port(client, family));

    key.remote_port = bound_port(client, family);
    check_owner(snapshot, &key, bound_port(accepted, family));

    key.protocol = 17;
    key.remote_port = 443;
    check_owner(snapshot, &key, bound_port(udp, family));
    check_owner(snapshot, &key, bound_port(connected_udp, family));
    app_snapshot_destroy(snapshot);

    struct app_resolver *resolver = app_resolver_create();
    char application[FLOW_APP_LEN] = "";
    const struct timespec delay = { .tv_nsec = 50000000 };

    CHECK(resolver != NULL);

    for (int attempt = 0; attempt < 100; attempt++) {
        app_resolver_lookup(&key, bound_port(connected_udp, family), application, resolver);

        if (application[0] != '\0') {
            break;
        }

        nanosleep(&delay, NULL);
    }

    CHECK(strcmp(application, "test_app_live") == 0);
    app_resolver_destroy(resolver);

    close(connected_udp);
    close(udp);
    close(accepted);
    close(client);
    close(tcp);
}

int main(void) {
    test_local_sockets(AF_INET);
    test_local_sockets(AF_INET6);
    app_resolver_destroy(NULL);

    return 0;
}
