#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "capture/capture.h"
#include "net/netif.h"
#include "flow/flow.h"
#include "proto/packet.h"
#include "proto/pktdump.h"
#include "store/store.h"
#include "dns/dns_cache.h"

#ifndef PIGEON_VERSION
#define PIGEON_VERSION "dev"
#endif

struct capture_context {
    unsigned long count;

    int verbose;
    int failed;

    struct flow *flows;
    struct store *store;
    int offline;
    struct ip_addr locals[64];
    size_t local_count;
    struct dns_cache *dns;
};

static void report_flow_error(struct capture_context *context) {
    perror("flow processing");

    if (context->store != NULL && store_error(context->store)[0] != '\0') {
        fprintf(stderr, "%s\n", store_error(context->store));
    }

    context->failed = 1;
    capture_stop();
}

static void tick_flows(int64_t now, void *user) {
    struct capture_context *context = user;

    if (context->dns != NULL) {
        dns_cache_expire(context->dns, now);
    }

    if (!context->failed && flow_tick(context->flows, now) == -1) {
        report_flow_error(context);
    }
}

static void observe_frame(const uint8_t *data, const uint32_t caplen,
                          const uint32_t wirelen, int64_t timestamp, void *user) {
    struct capture_context *context = user;
    struct packet_view packet;
    const int rc = packet_parse(data, caplen, &packet);

    context->count++;

    if (!context->failed && rc == 0 && context->dns != NULL &&
        dns_cache_observe_addresses(context->dns, &packet, context->locals, context->local_count, timestamp) == -1) {
        report_flow_error(context);
    }

    if (context->offline && context->flows != NULL) {
        tick_flows(timestamp, context);
    }

    if (!context->failed && rc == 0 && context->flows != NULL &&
        flow_observe(context->flows, &packet, timestamp) == -1) {
        report_flow_error(context);
    }

    if (context->verbose) {
        printf("#%lu caplen=%u wirelen=%u ", context->count, caplen, wirelen);

        if (rc == -1) {
            printf("malformed or truncated packet\n");
        } else {
            pktdump(stdout, &packet);
        }
    }
}

static void print_conversation(const struct flow_entry *entry, void *user) {
    struct capture_context *context = user;
    const struct flow_key *key = flow_entry_key(entry);
    struct store_row row;

    if (store_lookup(context->store, key, &row) != 1) {
        fprintf(stderr, "conversation lookup failed: %s\n", store_error(context->store));
        context->failed = 1;

        return;
    }

    const struct flow_delta *delta = &row.delta;

    char local[IP_ADDR_STR_LEN];
    char remote[IP_ADDR_STR_LEN];
    char endpoint[IP_ADDR_STR_LEN + 2];

    ip_addr_str(&key->remote_ip, remote);
    snprintf(endpoint, sizeof endpoint, key->remote_ip.family == 6 ? "[%s]" : "%s", remote);

    fprintf(stdout, "flow %s > %s:%u proto=%u packets_out=%" PRIu64
            " packets_in=%" PRIu64 " bytes_out=%" PRIu64 " bytes_in=%" PRIu64
            " first_seen=%" PRId64 " last_seen=%" PRId64 " name=%s\n",
            ip_addr_str(&key->us_ip, local), endpoint,
            key->remote_port, key->protocol, delta->packets_out, delta->packets_in,
            delta->bytes_out, delta->bytes_in, delta->first_seen, delta->last_seen,
            row.remote_name[0] != '\0' ? row.remote_name : "-");
}

int main(const int argc, char **argv) {
    struct capture_context context = { 0 };
    const char *source = NULL;
    int offline = 0;
    int invalid = 0;

    const char *local_addresses[64];
    size_t local_count = 0;
    const char *database_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) {
            context.verbose = 1;
        } else if (strcmp(argv[i], "--db") == 0 &&
                   database_path == NULL && i + 1 < argc) {
            database_path = argv[++i];
        } else if (strcmp(argv[i], "--local-ip") == 0 &&
                   local_count < 64 && i + 1 < argc) {
            local_addresses[local_count++] = argv[++i];
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

    if (invalid || (local_count != 0 && !offline) ||
        (database_path != NULL && offline && local_count == 0)) {
        fprintf(stderr, "pigeon %s\nusage: %s [--verbose] [--db <path>] [interface]\n"
                        "       %s [--verbose] [--db <path>] [--local-ip <IP> ...] -r <file.pcap>\n",
                PIGEON_VERSION, argv[0], argv[0]);

        return 2;
    }

    struct netif_info info = { 0 };
    const int tracking = !offline || local_count != 0;

    if (offline) {
        for (size_t i = 0; i < local_count; i++) {
            if (ip_addr_parse(local_addresses[i], &context.locals[i]) == -1) {
                fprintf(stderr, "invalid local IPv4/IPv6 address: %s\n", local_addresses[i]);

                return 2;
            }
        }

        context.local_count = local_count;
    } else {
        if (netif_select(source, &info) == -1 ||
            netif_addresses(info.name, context.locals, 64, &context.local_count) == -1) {
            perror("interface discovery");

            return 1;
        }
    }

    context.offline = offline;

    if (tracking) {
        char error[STORE_ERROR_LEN];

        if (database_path == NULL) {
            database_path = offline ? ":memory:" : "pigeon.db";
        }

        context.store = store_open(database_path, error);

        if (context.store == NULL) {
            fprintf(stderr, "storage initialization: %s\n", error);

            return 1;
        }

        context.flows = flow_create_addresses(context.locals, context.local_count, 4096, 10000);

        if (context.flows == NULL) {
            perror("flow initialization");
            store_close(context.store);

            return 1;
        }

        const time_t startup_time = offline ? 0 : time(NULL);

        if (!offline && startup_time == (time_t)-1) {
            perror("startup clock");
            flow_destroy(context.flows);
            store_close(context.store);

            return 1;
        }

        context.dns = dns_cache_create(context.store, 4096,
                                       offline ? INT64_MIN : (int64_t)startup_time);

        if (context.dns == NULL) {
            report_flow_error(&context);
            flow_destroy(context.flows);
            store_close(context.store);

            return 1;
        }

        flow_set_store(context.flows, context.store);
        flow_set_dns_cache(context.flows, context.dns);
    }

    int rc;

    if (offline) {
        rc = capture_run_file(source, observe_frame, &context);
    } else {
        fprintf(stderr, "pigeon %s capturing on %s\n", PIGEON_VERSION, info.name);

        if (info.gateway != 0) {
            char gateway[IPV4_STR_LEN];

            fprintf(stderr, "    IPv4 gateway %s\n", ipv4_addr_str(info.gateway, gateway));
        }

        for (size_t i = 0; i < context.local_count; i++) {
            char address[IP_ADDR_STR_LEN];

            fprintf(stderr, "    local address %s\n", ip_addr_str(&context.locals[i], address));
        }

        rc = capture_run_live_tick(info.name, observe_frame, tick_flows, &context);
    }

    fprintf(stderr, "pigeon stopped after %lu packets\n", context.count);

    if (context.flows != NULL) {
        if (flow_flush(context.flows) == -1) {
            report_flow_error(&context);
        }

        fprintf(stderr, "pigeon tracked %zu conversations\n", flow_count(context.flows));

        if (context.verbose && !context.failed) {
            flow_visit(context.flows, print_conversation, &context);
        }
    }

    flow_destroy(context.flows);
    dns_cache_destroy(context.dns);
    store_close(context.store);

    return rc == 0 && !context.failed ? 0 : 1;
}
