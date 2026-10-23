#define _GNU_SOURCE
#include "control/control.h"

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

struct control_server {
    int fd;
    uid_t owner;
    char path[CONTROL_PATH_LEN];
    dev_t device;
    ino_t inode;
};

int control_path(const char *database, char out[CONTROL_PATH_LEN]) {
    char *canonical = realpath(database, NULL);

    if (canonical == NULL) {
        return -1;
    }

    const int length = snprintf(out, CONTROL_PATH_LEN, "%s.control", canonical);

    free(canonical);

    if (length < 0 || length >= CONTROL_PATH_LEN) {
        errno = ENAMETOOLONG;

        return -1;
    }

    return 0;
}

static int send_all(int fd, const char *data) {
    size_t remaining = strlen(data);

    while (remaining != 0) {
        const ssize_t count = send(fd, data, remaining, MSG_NOSIGNAL);

        if (count < 0 && errno == EINTR) {
            continue;
        }

        if (count <= 0) {
            return -1;
        }

        data += count;
        remaining -= (size_t)count;
    }

    return 0;
}

struct control_server *control_server_open(const char *database, uid_t owner) {
    struct control_server *server = calloc(1, sizeof *server);

    if (server == NULL) {
        return NULL;
    }

    server->fd = -1;
    server->owner = owner;

    if (control_path(database, server->path) == -1) {
        goto failed;
    }

    struct sockaddr_un address = { .sun_family = AF_UNIX };

    memcpy(address.sun_path, server->path, strlen(server->path) + 1);

    /* Never replace a regular file, symlink, another owner's socket, or a
     * live collector. Only remove our own socket left after a crash. */
    struct stat previous;

    if (lstat(server->path, &previous) == 0) {
        if (!S_ISSOCK(previous.st_mode) || previous.st_uid != geteuid()) {
            errno = EEXIST;
            goto failed;
        }

        const int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

        if (probe == -1) {
            goto failed;
        }

        const int connected = connect(probe, (const struct sockaddr *)&address, sizeof address);
        const int reason = errno;

        close(probe);

        if (connected == 0 || reason != ECONNREFUSED) {
            errno = EADDRINUSE;
            goto failed;
        }

        if (unlink(server->path) == -1) {
            goto failed;
        }
    } else if (errno != ENOENT) {
        goto failed;
    }

    server->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

    if (server->fd == -1 || bind(server->fd, (const struct sockaddr *)&address, sizeof address) == -1) {
        goto failed;
    }

    if (lstat(server->path, &previous) == -1) {
        goto failed;
    }

    server->device = previous.st_dev;
    server->inode = previous.st_ino;

    /* Peer credentials enforce authorization even for a root-owned socket. */
    if (chmod(server->path, 0666) == -1 || listen(server->fd, 8) == -1) {
        goto failed;
    }

    return server;

failed:;

    const int saved_errno = errno;

    control_server_close(server);
    errno = saved_errno;

    return NULL;
}

void control_server_poll(struct control_server *server, control_handler handler, void *user) {
    if (server == NULL) {
        return;
    }

    /* One bounded request per maintenance tick; clients cannot starve capture. */
    const int client = accept4(server->fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);

    if (client == -1) {
        return;
    }

    struct ucred credentials;
    socklen_t length = sizeof credentials;
    char request[1024] = "";
    size_t used = 0;

    const int authorized = getsockopt(client, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0 &&
                           (credentials.uid == 0 || credentials.uid == server->owner);

    /* A short deadline also covers clients connecting before sending. */
    struct pollfd descriptor = { .fd = client, .events = POLLIN };

    for (int attempt = 0; attempt < 4 && used < sizeof request - 1; attempt++) {
        if (poll(&descriptor, 1, 25) <= 0) {
            continue;
        }

        const ssize_t count = recv(client, request + used, sizeof request - 1 - used, 0);

        if (count <= 0) {
            break;
        }

        used += (size_t)count;
        request[used] = '\0';

        char *newline = strchr(request, '\n');

        if (newline != NULL) {
            *newline = '\0';

            char reply[CONTROL_REPLY_LEN] = "";

            if (authorized) {
                handler(request, reply, sizeof reply, user);
            } else {
                snprintf(reply, sizeof reply, "ERROR\tNot authorized to control this collector\n");
            }

            send_all(client, reply);
            close(client);

            return;
        }
    }

    send_all(client, "ERROR\tInvalid or incomplete control request\n");
    close(client);
}

void control_server_close(struct control_server *server) {
    if (server == NULL) {
        return;
    }

    if (server->fd != -1) {
        close(server->fd);
    }

    struct stat current;

    if (server->inode != 0 && lstat(server->path, &current) == 0 &&
        current.st_dev == server->device && current.st_ino == server->inode) {
        unlink(server->path);
    }

    free(server);
}

int control_request(const char *database, const char *request, char *reply, size_t capacity) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };

    if (capacity < 2 || control_path(database, address.sun_path) == -1) {
        return -1;
    }

    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (fd == -1) {
        return -1;
    }

    const struct timeval timeout = { .tv_sec = 10 };
    int result = -1;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) == -1 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) == -1 ||
        connect(fd, (const struct sockaddr *)&address, sizeof address) == -1 ||
        send_all(fd, request) == -1 || send_all(fd, "\n") == -1) {
        goto done;
    }

    size_t used = 0;

    while (used < capacity - 1) {
        const ssize_t count = recv(fd, reply + used, capacity - 1 - used, 0);

        if (count == -1 && errno == EINTR) {
            continue;
        }

        if (count == -1) {
            goto done;
        }

        if (count == 0) {
            reply[used] = '\0';
            result = used != 0 ? 0 : -1;
            goto done;
        }

        used += (size_t)count;
    }

    errno = EMSGSIZE;

done:;

    const int saved_errno = errno;

    close(fd);
    errno = saved_errno;

    return result;
}

#else

#include <errno.h>

int control_path(const char *database, char out[CONTROL_PATH_LEN]) {
    (void)database;
    (void)out;
    errno = ENOSYS;

    return -1;
}

struct control_server *control_server_open(const char *database, uid_t owner) {
    (void)database;
    (void)owner;
    errno = ENOSYS;

    return NULL;
}

void control_server_poll(struct control_server *server, control_handler handler, void *user) {
    (void)server;
    (void)handler;
    (void)user;
}

void control_server_close(struct control_server *server) {
    (void)server;
}

int control_request(const char *database, const char *request, char *reply, size_t capacity) {
    (void)database;
    (void)request;
    (void)reply;
    (void)capacity;
    errno = ENOSYS;

    return -1;
}

#endif
