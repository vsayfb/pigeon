#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "capture/capture.h"

#ifndef PIGEON_VERSION
#define PIGEON_VERSION "dev"
#endif

/* Prints a running count and the captured/wire length of each packet. */
static void print_length(const uint8_t *data, const uint32_t caplen,
                         const uint32_t wirelen, void *user) {
    (void)data;

    unsigned long *count = user;

    (*count)++;

    printf("#%lu caplen=%u wirelen=%u\n", *count, caplen, wirelen);
}

int main(const int argc, char **argv) {
    const int offline = argc == 3 && strcmp(argv[1], "-r") == 0;

    if (!offline && argc != 2) {
        fprintf(stderr, "pigeon %s\nusage: %s <interface>\n"
                        "       %s -r <file.pcap>\n",
                PIGEON_VERSION, argv[0], argv[0]);

        return 2;
    }

    unsigned long count = 0;
    int rc;

    if (offline) {
        rc = capture_run_file(argv[2], print_length, &count);
    } else {
        fprintf(stderr, "pigeon %s capturing on %s\n", PIGEON_VERSION, argv[1]);
        rc = capture_run_live(argv[1], print_length, &count);
    }

    fprintf(stderr, "pigeon stopped after %lu packets\n", count);

    return rc == 0 ? 0 : 1;
}
