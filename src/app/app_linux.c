#include "app/app_internal.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_SOCKETS 131072
#define MAX_FDS 262144

static int append_socket(struct app_snapshot *snapshot, const struct inet_diag_msg *message,
                           uint8_t protocol) {
    if (message->idiag_inode == 0) {
        return 0;
    }

    if (snapshot->count == MAX_SOCKETS) {
        errno = EOVERFLOW;

        return -1;
    }

    if (snapshot->count % 256 == 0) {
        void *grown = realloc(snapshot->sockets, (snapshot->count + 256) * sizeof *snapshot->sockets);

        if (grown == NULL) {
            return -1;
        }

        snapshot->sockets = grown;
    }

    struct app_socket *socket = &snapshot->sockets[snapshot->count++];

    memset(socket, 0, sizeof *socket);
    socket->local.family = socket->remote.family = message->idiag_family == AF_INET ? 4 : 6;
    memcpy(socket->local.bytes, message->id.idiag_src, ip_addr_size(&socket->local));
    memcpy(socket->remote.bytes, message->id.idiag_dst, ip_addr_size(&socket->remote));
    socket->local_port = ntohs(message->id.idiag_sport);
    socket->remote_port = ntohs(message->id.idiag_dport);
    socket->protocol = protocol;
    socket->inode = message->idiag_inode;

    /* A dual-stack TCP connection may be reported as IPv4-mapped IPv6. */
    static const unsigned char mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255 };

    if (socket->local.family == 6 && memcmp(socket->local.bytes, mapped, 12) == 0 &&
        memcmp(socket->remote.bytes, mapped, 12) == 0) {
        memmove(socket->local.bytes, socket->local.bytes + 12, 4);
        memmove(socket->remote.bytes, socket->remote.bytes + 12, 4);
        socket->local.family = socket->remote.family = 4;
    }

    return 0;
}

static int dump_sockets(int fd, uint8_t family, uint8_t protocol, uint32_t sequence,
                          struct app_snapshot *snapshot) {
    const struct {
        struct nlmsghdr header;
        struct inet_diag_req_v2 query;
    } request = {
        .header = { .nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_req_v2)),
                    .nlmsg_type = SOCK_DIAG_BY_FAMILY,
                    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP, .nlmsg_seq = sequence },
        .query = { .sdiag_family = family, .sdiag_protocol = protocol, .idiag_states = UINT32_MAX }
    };
    const struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };

    if (sendto(fd, &request, request.header.nlmsg_len, 0,
               (const struct sockaddr *)&kernel, sizeof kernel) == -1) {
        return -1;
    }

    for (;;) {
        union {
            struct nlmsghdr alignment;
            unsigned char bytes[65536];
        } buffer;
        struct sockaddr_nl sender = { 0 };
        struct iovec vector = { .iov_base = buffer.bytes, .iov_len = sizeof buffer.bytes };
        struct msghdr envelope = { .msg_name = &sender, .msg_namelen = sizeof sender,
                                   .msg_iov = &vector, .msg_iovlen = 1 };
        const ssize_t received = recvmsg(fd, &envelope, 0);

        if (received <= 0 || (envelope.msg_flags & MSG_TRUNC) || sender.nl_pid != 0 ||
            envelope.msg_namelen < sizeof sender || sender.nl_family != AF_NETLINK) {
            return -1;
        }

        int remaining = (int)received;

        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer.bytes;
             NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != sequence || (header->nlmsg_flags & NLM_F_DUMP_INTR)) {
                errno = EAGAIN;

                return -1;
            }

            if (header->nlmsg_type == NLMSG_DONE) {
                if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(int))) {
                    int status;

                    memcpy(&status, NLMSG_DATA(header), sizeof status);

                    if (status != 0) {
                        errno = status < 0 ? -status : EIO;

                        return -1;
                    }
                }

                return 0;
            }

            if (header->nlmsg_type == NLMSG_ERROR) {
                errno = EIO;

                if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                    const struct nlmsgerr *error = NLMSG_DATA(header);

                    if (error->error < 0) {
                        errno = -error->error;
                    }
                }

                return -1;
            }

            if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
                errno = EPROTO;

                return -1;
            }

            const struct inet_diag_msg *message = NLMSG_DATA(header);

            if (message->idiag_family != family || append_socket(snapshot, message, protocol) == -1) {
                return -1;
            }
        }

        if (remaining != 0) {
            errno = EPROTO;

            return -1;
        }
    }
}

static int compare_inode(const void *a, const void *b) {
    const struct app_socket *left = a;
    const struct app_socket *right = b;

    return (left->inode > right->inode) - (left->inode < right->inode);
}

static int numeric(const char *name) {
    if (*name == '\0') {
        return 0;
    }

    for (; *name != '\0'; name++) {
        if (*name < '0' || *name > '9') {
            return 0;
        }
    }

    return 1;
}

static int read_application(int directory, char out[FLOW_APP_LEN]) {
    char path[4096];
    const ssize_t length = readlinkat(directory, "exe", path, sizeof path - 1);

    if (length <= 0 || (size_t)length >= sizeof path - 1) {
        return -1;
    }

    path[length] = '\0';

    const char *suffix = " (deleted)";
    const size_t suffix_length = strlen(suffix);

    if ((size_t)length > suffix_length && strcmp(path + length - suffix_length, suffix) == 0) {
        path[length - suffix_length] = '\0';
    }

    const char *basename = strrchr(path, '/');

    if (basename == NULL || basename[1] == '\0' || strlen(basename + 1) >= FLOW_APP_LEN) {
        return -1;
    }

    strcpy(out, basename + 1);

    return 0;
}

static void record_owner(struct app_snapshot *snapshot, uint32_t inode, const char *application) {
    struct app_socket search = { .inode = inode };
    struct app_socket *found = bsearch(&search, snapshot->sockets, snapshot->count,
                                       sizeof *snapshot->sockets, compare_inode);

    if (found == NULL) {
        return;
    }

    /* An inode can appear more than once in a dump; update every occurrence. */
    size_t index = (size_t)(found - snapshot->sockets);

    while (index != 0 && snapshot->sockets[index - 1].inode == inode) {
        index--;
    }

    for (; index < snapshot->count && snapshot->sockets[index].inode == inode; index++) {
        struct app_socket *socket = &snapshot->sockets[index];

        if (application[0] == '\0' ||
            (socket->owner_seen && strcmp(socket->application, application) != 0)) {
            socket->ambiguous = 1;
        }

        if (!socket->owner_seen) {
            strcpy(socket->application, application);
        }

        socket->owner_seen = 1;
    }
}

static int read_owners(struct app_snapshot *snapshot) {
    DIR *processes = opendir("/proc");

    if (processes == NULL) {
        return -1;
    }

    struct dirent *process;
    size_t scanned = 0;
    int result = 0;

    while ((process = readdir(processes)) != NULL) {
        if (!numeric(process->d_name)) {
            continue;
        }

        const int directory = openat(dirfd(processes), process->d_name, O_DIRECTORY | O_RDONLY | O_CLOEXEC);

        if (directory == -1) {
            continue;
        }

        const int fd = openat(directory, "fd", O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        DIR *descriptors = fd == -1 ? NULL : fdopendir(fd);
        char application[FLOW_APP_LEN] = "";

        read_application(directory, application);

        if (descriptors == NULL) {
            if (fd != -1) {
                close(fd);
            }

            close(directory);
            continue;
        }

        struct dirent *descriptor;

        while ((descriptor = readdir(descriptors)) != NULL) {
            if (!numeric(descriptor->d_name)) {
                continue;
            }

            if (++scanned > MAX_FDS) {
                result = -1;
                break;
            }

            char target[64];
            const ssize_t length = readlinkat(dirfd(descriptors), descriptor->d_name, target, sizeof target - 1);
            unsigned long inode;
            int consumed = 0;

            if (length <= 0 || (size_t)length >= sizeof target - 1) {
                continue;
            }

            target[length] = '\0';

            if (sscanf(target, "socket:[%lu]%n", &inode, &consumed) == 1 &&
                consumed == length && inode <= UINT32_MAX) {
                char current[FLOW_APP_LEN] = "";

                /* Refuse ownership if exec changed while this process was scanned. */
                if (read_application(directory, current) == -1 || strcmp(current, application) != 0) {
                    current[0] = '\0';
                }

                record_owner(snapshot, (uint32_t)inode, current);
            }
        }

        closedir(descriptors);
        close(directory);

        if (result == -1) {
            errno = EOVERFLOW;
            break;
        }
    }

    closedir(processes);

    return result;
}

struct app_snapshot *app_snapshot_read(void) {
    struct app_snapshot *snapshot = calloc(1, sizeof *snapshot);

    if (snapshot == NULL) {
        return NULL;
    }

    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    const struct timeval timeout = { .tv_usec = 250000 };

    if (fd == -1) {
        app_snapshot_destroy(snapshot);

        return NULL;
    }

    int result = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    const uint8_t families[] = { AF_INET, AF_INET6 };
    const uint8_t protocols[] = { IPPROTO_TCP, IPPROTO_UDP };
    uint32_t sequence = 0;

    for (size_t family = 0; family < 2 && result == 0; family++) {
        for (size_t protocol = 0; protocol < 2 && result == 0; protocol++) {
            const size_t before = snapshot->count;

            result = dump_sockets(fd, families[family], protocols[protocol], ++sequence, snapshot);

            if (result == -1 && (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT || errno == ENOENT)) {
                snapshot->count = before;
                result = 0;
            }
        }
    }

    close(fd);

    if (result == 0 && snapshot->count > 0) {
        qsort(snapshot->sockets, snapshot->count, sizeof *snapshot->sockets, compare_inode);
        result = read_owners(snapshot);
    }

    if (result == -1) {
        app_snapshot_destroy(snapshot);

        return NULL;
    }

    return snapshot;
}
