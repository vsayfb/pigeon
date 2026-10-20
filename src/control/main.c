#include "control/control.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static int stopped_error(int error) {
    return error == ENOENT || error == ECONNREFUSED;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "status") != 0 && strcmp(argv[1], "stop") != 0)) {
        fprintf(stderr, "usage: %s status|stop <database>\n", argv[0]);

        return 2;
    }

    const int stop = strcmp(argv[1], "stop") == 0;
    char reply[CONTROL_REPLY_LEN];

    if (control_request(argv[2], stop ? "STOP" : "STATUS", reply, sizeof reply) == -1) {
        if (stopped_error(errno)) {
            puts("Pigeon is stopped.");

            return stop ? 0 : 1;
        }

        perror("pigeon control");

        return 2;
    }

    /* Older foreground collectors support LIST, but not managed shutdown. */
    if (!stop && strncmp(reply, "ERROR\tInvalid interface request", 31) == 0) {
        if (control_request(argv[2], "LIST", reply, sizeof reply) == -1) {
            perror("pigeon control");

            return 2;
        }
    }

    if (stop && strncmp(reply, "ERROR\tInvalid interface request", 31) == 0) {
        fprintf(stderr, "pigeon: this older collector must be stopped in its original terminal with Ctrl+C\n");

        return 2;
    }

    if (strncmp(reply, "OK\t", 3) != 0) {
        fprintf(stderr, "pigeon: %s", strncmp(reply, "ERROR\t", 6) == 0 ? reply + 6 : reply);

        return 2;
    }

    if (!stop) {
        char interface[64];
        char mode[16];

        if (sscanf(reply, "OK\t%63s\t%15s", interface, mode) != 2) {
            fprintf(stderr, "pigeon: invalid collector status\n");

            return 2;
        }

        printf("Pigeon is running on %s (%s).\n", interface, mode);

        return 0;
    }

    char path[CONTROL_PATH_LEN];

    if (control_path(argv[2], path) == -1) {
        perror("pigeon shutdown");

        return 2;
    }

    /* The collector removes this socket only after its final database flush. */
    for (int attempt = 0; attempt < 150; attempt++) {
        struct stat info;

        if (lstat(path, &info) == -1) {
            if (errno == ENOENT) {
                puts("Pigeon stopped.");

                return 0;
            }

            perror("pigeon shutdown");

            return 2;
        }

        const struct timespec delay = { .tv_nsec = 100000000 };

        nanosleep(&delay, NULL);
    }

    fprintf(stderr, "pigeon: shutdown is still finishing; check pigeon logs\n");

    return 2;
}
