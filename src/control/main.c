#include "control/control.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static int stopped_error(int error) {
    return error == ENOENT || error == ECONNREFUSED;
}

static int copy_database(const char *source, const char *destination) {
    sqlite3 *input = NULL;
    sqlite3 *output = NULL;
    int result = 1;
    const int fd = open(destination, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd == -1) {
        perror("database destination");

        return 1;
    }

    close(fd);

    if (sqlite3_open_v2(source, &input, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK ||
        sqlite3_open_v2(destination, &output, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database for backup\n");
    } else {
        sqlite3_backup *backup = sqlite3_backup_init(output, "main", input, "main");

        if (backup != NULL) {
            int rc;
            unsigned int retries = 0;

            do {
                rc = sqlite3_backup_step(backup, 128);

                if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
                    sqlite3_sleep(50);
                    retries++;
                }
            } while (rc == SQLITE_OK || ((rc == SQLITE_BUSY || rc == SQLITE_LOCKED) && retries < 200));

            const int finished = sqlite3_backup_finish(backup);

            if (rc == SQLITE_DONE && finished == SQLITE_OK) {
                result = 0;
            }
        }

        if (result != 0) {
            fprintf(stderr, "Database backup failed: %s\n", sqlite3_errmsg(output));
        }
    }

    sqlite3_close(output);
    sqlite3_close(input);

    if (result != 0) {
        unlink(destination);
    }

    return result;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "backup") == 0) {
        return copy_database(argv[2], argv[3]);
    }

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
