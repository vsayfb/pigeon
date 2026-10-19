#include <stdio.h>
#include <string.h>

#include "capture/capture.h"
#include "net/netif.h"
#include "proto/packet.h"
#include "proto/pktdump.h"

#ifndef PIGEON_VERSION
#define PIGEON_VERSION "dev"
#endif

struct capture_context {
    unsigned long count;

    int verbose;
};

static void observe_frame(const uint8_t *data, const uint32_t caplen,
                          const uint32_t wirelen, void *user) {
    struct capture_context *context = user;
    struct packet_view packet;
    const int rc = packet_parse(data, caplen, &packet);

    context->count++;

    if (context->verbose) {
        printf("#%lu caplen=%u wirelen=%u ", context->count, caplen, wirelen);

        if (rc == -1) {
            printf("malformed or truncated packet\n");
        } else {
            pktdump(stdout, &packet);
        }
    }
}

int main(const int argc, char **argv) {
    struct capture_context context = { 0 };
    const char *source = NULL;
    int offline = 0;
    int invalid = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            context.verbose = 1;
        } else if (strcmp(argv[i], "-r") == 0 && source == NULL && i + 1 < argc) {
            offline = 1;
            source = argv[++i];
        } else if (argv[i][0] != '-' && source == NULL) {
            source = argv[i];
        } else {
            invalid = 1;

            break;
        }
    }

    if (invalid) {
        fprintf(stderr, "pigeon %s\nusage: %s [--verbose] [interface]\n"
                        "       %s [--verbose] -r <file.pcap>\n",
                PIGEON_VERSION, argv[0], argv[0]);

        return 2;
    }

    int rc;

    if (offline) {
        rc = capture_run_file(source, observe_frame, &context);
    } else {
        struct netif_info info;

        if (netif_lookup_on(0x01010101, source, &info) == -1) {
            perror("interface discovery");

            return 1;
        }

        char local[IPV4_STR_LEN];
        char gateway[IPV4_STR_LEN];

        fprintf(stderr, "pigeon %s capturing on %s local=%s gateway=%s\n",
                PIGEON_VERSION, info.name, ipv4_addr_str(info.local_ip, local),
                ipv4_addr_str(info.gateway, gateway));

        rc = capture_run_live(info.name, observe_frame, &context);
    }

    fprintf(stderr, "pigeon stopped after %lu packets\n", context.count);

    return rc == 0 ? 0 : 1;
}
