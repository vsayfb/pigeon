#include "net/netif.h"
#include "net/netif_linux.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

int netif_route_decode(const void *data, size_t len, struct netif_route *out) {
    struct nlmsghdr header;
    struct rtmsg message;
    struct netif_route route = { 0 };
    const unsigned char *bytes = data;

    if (len < NLMSG_HDRLEN) {
        errno = EPROTO;

        return -1;
    }

    memcpy(&header, bytes, sizeof header);

    if (header.nlmsg_len < NLMSG_HDRLEN || header.nlmsg_len > len) {
        errno = EPROTO;

        return -1;
    }

    if (header.nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr error;

        if (header.nlmsg_len < NLMSG_LENGTH(sizeof error)) {
            errno = EPROTO;

            return -1;
        }

        memcpy(&error, bytes + NLMSG_HDRLEN, sizeof error);
        errno = error.error < 0 && error.error >= -4095 ? -error.error : EPROTO;

        return -1;
    }

    if (header.nlmsg_type != RTM_NEWROUTE ||
        header.nlmsg_len < NLMSG_LENGTH(sizeof message)) {
        errno = EPROTO;

        return -1;
    }

    memcpy(&message, bytes + NLMSG_HDRLEN, sizeof message);

    if (message.rtm_family != AF_INET || message.rtm_type != RTN_UNICAST) {
        errno = ENETUNREACH;

        return -1;
    }

    size_t offset = NLMSG_LENGTH(sizeof message);

    while (offset < header.nlmsg_len) {
        struct rtattr attribute;
        const size_t remaining = header.nlmsg_len - offset;

        if (remaining < sizeof attribute) {
            errno = EPROTO;

            return -1;
        }

        memcpy(&attribute, bytes + offset, sizeof attribute);

        if (attribute.rta_len < RTA_LENGTH(0) || attribute.rta_len > remaining) {
            errno = EPROTO;

            return -1;
        }

        if (attribute.rta_type == RTA_OIF || attribute.rta_type == RTA_PREFSRC ||
            attribute.rta_type == RTA_GATEWAY) {
            uint32_t value;

            if (attribute.rta_len != RTA_LENGTH(sizeof value)) {
                errno = EPROTO;

                return -1;
            }

            memcpy(&value, bytes + offset + RTA_LENGTH(0), sizeof value);

            if (attribute.rta_type == RTA_OIF) {
                route.index = value;
            } else if (attribute.rta_type == RTA_PREFSRC) {
                route.local_ip = ntohl(value);
            } else {
                route.gateway = ntohl(value);
            }
        }

        const size_t step = RTA_ALIGN(attribute.rta_len);

        if (step > remaining) {
            errno = EPROTO;

            return -1;
        }

        offset += step;
    }

    if (route.index == 0 || route.local_ip == 0) {
        errno = ENETUNREACH;

        return -1;
    }

    *out = route;

    return 0;
}

int netif_lookup_on(uint32_t destination, const char *name, struct netif_info *out) {
    struct {
        struct nlmsghdr header;
        struct rtmsg route;
        struct rtattr destination_attribute;
        uint32_t destination;
        struct rtattr interface_attribute;
        uint32_t index;
    } request = { 0 };

    const struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    const struct timeval timeout = { .tv_sec = 2 };

    unsigned char reply[8192];

    struct netif_route route;
    struct netif_info info = { 0 };

    if (name != NULL) {
        request.index = if_nametoindex(name);

        if (request.index == 0) {
            return -1;
        }
    }

    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

    if (fd == -1) {
        return -1;
    }

    request.header.nlmsg_len = NLMSG_LENGTH(sizeof request.route) +
                              RTA_LENGTH(sizeof request.destination);

    if (name != NULL) {
        request.interface_attribute.rta_type = RTA_OIF;
        request.interface_attribute.rta_len = RTA_LENGTH(sizeof request.index);
        request.header.nlmsg_len += RTA_LENGTH(sizeof request.index);
    }

    request.header.nlmsg_type = RTM_GETROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST;
    request.header.nlmsg_seq = 1;
    request.route.rtm_family = AF_INET;
    request.route.rtm_dst_len = 32;
    request.destination_attribute.rta_type = RTA_DST;
    request.destination_attribute.rta_len = RTA_LENGTH(sizeof request.destination);
    request.destination = htonl(destination);

    int rc = -1;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) == -1) {
        goto done;
    }

    if (sendto(fd, &request, request.header.nlmsg_len, 0,
               (const struct sockaddr *)&kernel, sizeof kernel) == -1) {
        goto done;
    }

    ssize_t length;

    do {
        length = recv(fd, reply, sizeof reply, MSG_TRUNC);
    } while (length == -1 && errno == EINTR);

    if (length == -1) {
        goto done;
    }

    if ((size_t)length > sizeof reply) {
        errno = EMSGSIZE;
        goto done;
    }

    if (netif_route_decode(reply, (size_t)length, &route) == -1) {
        goto done;
    }

    if (if_indextoname(route.index, info.name) == NULL) {
        goto done;
    }

    info.local_ip = route.local_ip;
    info.gateway = route.gateway;
    *out = info;
    rc = 0;

done:;

    const int saved_errno = errno;

    close(fd);
    errno = saved_errno;

    return rc;
}

int netif_lookup(uint32_t destination, struct netif_info *out) {
    return netif_lookup_on(destination, NULL, out);
}

int netif_addresses(const char *name, struct ip_addr *out, size_t capacity, size_t *count) {
    struct ifaddrs *addresses;

    if (getifaddrs(&addresses) == -1) {
        return -1;
    }

    *count = 0;

    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr != NULL && strcmp(entry->ifa_name, name) == 0 &&
            (entry->ifa_addr->sa_family == AF_INET || entry->ifa_addr->sa_family == AF_INET6)) {
            (*count)++;
        }
    }

    if (capacity != 0 && *count > capacity) {
        freeifaddrs(addresses);
        errno = ENOSPC;

        return -1;
    }

    size_t written = 0;

    for (const struct ifaddrs *entry = addresses; capacity != 0 && entry != NULL;
         entry = entry->ifa_next) {
        if (entry->ifa_addr == NULL || strcmp(entry->ifa_name, name) != 0) {
            continue;
        }

        struct ip_addr address = { 0 };

        if (entry->ifa_addr->sa_family == AF_INET) {
            const struct sockaddr_in *v4 = (const struct sockaddr_in *)entry->ifa_addr;

            address.family = 4;
            memcpy(address.bytes, &v4->sin_addr, 4);
        } else if (entry->ifa_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)entry->ifa_addr;

            address.family = 6;
            memcpy(address.bytes, &v6->sin6_addr, 16);
        } else {
            continue;
        }

        out[written++] = address;
    }

    freeifaddrs(addresses);

    if (*count == 0) {
        errno = EADDRNOTAVAIL;

        return -1;
    }

    return 0;
}

int netif_select(const char *name, struct netif_info *out) {
    if (netif_lookup_on(0x01010101, name, out) == 0) {
        return 0;
    }

    struct netif_info info = { 0 };

    if (name != NULL) {
        if (strlen(name) >= sizeof info.name || if_nametoindex(name) == 0) {
            errno = ENODEV;

            return -1;
        }

        memcpy(info.name, name, strlen(name) + 1);
        *out = info;

        return 0;
    }

    struct sockaddr_in6 destination = { .sin6_family = AF_INET6, .sin6_port = htons(53) };
    struct sockaddr_in6 source;
    socklen_t source_len = sizeof source;

    inet_pton(AF_INET6, "2001:4860:4860::8888", &destination.sin6_addr);

    const int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    if (fd == -1) {
        return -1;
    }

    if (connect(fd, (const struct sockaddr *)&destination, sizeof destination) == -1 ||
        getsockname(fd, (struct sockaddr *)&source, &source_len) == -1) {
        const int saved_errno = errno;

        close(fd);
        errno = saved_errno;

        return -1;
    }

    close(fd);

    struct ifaddrs *addresses;

    if (getifaddrs(&addresses) == -1) {
        return -1;
    }

    int found = 0;

    for (const struct ifaddrs *entry = addresses; entry != NULL; entry = entry->ifa_next) {
        if (entry->ifa_addr == NULL || entry->ifa_addr->sa_family != AF_INET6) {
            continue;
        }

        const struct sockaddr_in6 *address = (const struct sockaddr_in6 *)entry->ifa_addr;

        if (memcmp(&source.sin6_addr, &address->sin6_addr, 16) == 0 &&
            strlen(entry->ifa_name) < sizeof info.name) {
            memcpy(info.name, entry->ifa_name, strlen(entry->ifa_name) + 1);
            found = 1;
            break;
        }
    }

    freeifaddrs(addresses);

    if (!found) {
        errno = EADDRNOTAVAIL;

        return -1;
    }

    *out = info;

    return 0;
}
