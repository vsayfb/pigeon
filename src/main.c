#include <arpa/inet.h>
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "capture/capture.h"
#include "control/control.h"
#include "app/app.h"
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
    int debug_attribution;
    int failed;

    struct flow *flows;
    struct store *store;
    int offline;
    struct ip_addr locals[64];
    size_t local_count;
    struct dns_cache *dns;
    struct app_resolver *applications;
    struct control_server *control;
    struct capture_source *pending_source;
    struct flow *pending_flows;
    struct ip_addr pending_locals[64];
    size_t pending_local_count;
    struct netif_info pending_info;
    struct netif_info current_info;
    int automatic;
    int pending_automatic;
};

static void report_flow_error(struct capture_context *context) {
    perror("flow processing");

    if (context->store != NULL && store_error(context->store)[0] != '\0') {
        fprintf(stderr, "%s\n", store_error(context->store));
    }

    context->failed = 1;
    capture_stop();
}

static void control_command(const char *request, char *reply, size_t capacity, void *user) {
    struct capture_context *context = user;

    if (strcmp(request, "LIST") == 0) {
        const int used = snprintf(reply, capacity, "OK\t%s\t%s\n", context->current_info.name,
                                  context->automatic ? "auto" : "manual");

        if (used < 0 || (size_t)used >= capacity ||
            capture_interface_list(reply + used, capacity - (size_t)used) == -1) {
            snprintf(reply, capacity, "ERROR\tInterface discovery failed\n");
        }

        return;
    }

    const int automatic = strcmp(request, "AUTO") == 0;
    const char *name = strncmp(request, "SELECT ", 7) == 0 ? request + 7 : NULL;

    if (!automatic && (name == NULL || name[0] == '\0' || strlen(name) >= NETIF_NAME_LEN ||
                       strpbrk(name, " \t\r\n/") != NULL)) {
        snprintf(reply, capacity, "ERROR\tInvalid interface request\n");

        return;
    }

    struct netif_info preferred = { 0 };
    struct netif_info info;
    char selected[NETIF_NAME_LEN];
    const int have_preferred = netif_select(name, &preferred) == 0;
    const char *candidate = automatic ? (have_preferred ? preferred.name : NULL) : name;

    if (capture_select_interface(candidate, !automatic, selected, sizeof selected) == -1 ||
        netif_select(selected, &info) == -1 ||
        netif_addresses(selected, context->pending_locals, 64, &context->pending_local_count) == -1) {
        snprintf(reply, capacity, "ERROR\tInterface unavailable or unsupported; capture unchanged\n");

        return;
    }

    if (strcmp(selected, context->current_info.name) == 0) {
        context->automatic = automatic;
        snprintf(reply, capacity, "OK\t%s\t%s\n", selected, automatic ? "auto" : "manual");

        return;
    }

    struct capture_source *source = capture_source_open(selected);
    struct flow *flows = flow_create_addresses(context->pending_locals, context->pending_local_count, 4096, 10000);

    if (source == NULL || flows == NULL) {
        capture_source_close(source);
        flow_destroy(flows);
        snprintf(reply, capacity, "ERROR\tCannot prepare interface; capture unchanged\n");

        return;
    }

    if (flow_flush(context->flows) == -1) {
        capture_source_close(source);
        flow_destroy(flows);
        snprintf(reply, capacity, "ERROR\tCannot flush pending traffic; capture unchanged\n");

        return;
    }

    flow_set_store(flows, context->store);
    flow_set_dns_cache(flows, context->dns);

    if (context->applications != NULL) {
        flow_set_application_resolver(flows, app_resolver_lookup, context->applications);
    }

    context->pending_source = source;
    context->pending_flows = flows;
    context->pending_info = info;
    context->pending_automatic = automatic;
    capture_stop();
    snprintf(reply, capacity, "OK\t%s\t%s\n", selected, automatic ? "auto" : "manual");
}

static void tick_flows(int64_t now, void *user) {
    struct capture_context *context = user;

    if (!context->failed) {
        control_server_poll(context->control, control_command, context);
    }

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

    char peer[IP_ADDR_STR_LEN + 10];

    if (protocol_has_ports(key->protocol)) {
        snprintf(peer, sizeof peer, "%s:%u", endpoint, key->remote_port);
    } else {
        snprintf(peer, sizeof peer, "%s", endpoint);
    }

    fprintf(stdout, "flow %s > %s proto=%u packets_out=%" PRIu64
            " packets_in=%" PRIu64 " bytes_out=%" PRIu64 " bytes_in=%" PRIu64
            " first_seen=%" PRId64 " last_seen=%" PRId64 " name=%s app=",
            ip_addr_str(&key->us_ip, local), peer,
            key->protocol, delta->packets_out, delta->packets_in,
            delta->bytes_out, delta->bytes_in, delta->first_seen, delta->last_seen,
            row.remote_name[0] != '\0' ? row.remote_name : "-");

    const char *application = key->application[0] ? key->application : "unresolved";

    for (size_t i = 0; application[i] != '\0'; i++) {
        const unsigned char byte = (unsigned char)application[i];

        putchar(byte >= 32 && byte <= 126 ? byte : '?');
    }

    if (row.quic) {
        fputs(" label=QUIC(UDP)", stdout);
    }

    putchar('\n');
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
        } else if (strcmp(argv[i], "--debug-attribution") == 0) {
            context.debug_attribution = 1;
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

    if (invalid || (offline && context.debug_attribution) || (local_count != 0 && !offline) ||
        (database_path != NULL && offline && local_count == 0)) {
        fprintf(stderr, "pigeon %s\nusage: %s [--verbose] [--debug-attribution] [--db <path>] [interface]\n"
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
        struct netif_info preferred = { 0 };
        char selected[NETIF_NAME_LEN];
        const int have_preferred = netif_select(source, &preferred) == 0;

        if (source != NULL && !have_preferred) {
            perror("interface discovery");

            return 1;
        }

        const char *candidate = source != NULL ? source : (have_preferred ? preferred.name : NULL);

        if (capture_select_interface(candidate, source != NULL, selected, sizeof selected) == -1) {
            return 1;
        }

        if (netif_select(selected, &info) == -1 ||
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

        if (!offline) {
            context.applications = app_resolver_create();

            if (context.applications == NULL) {
                perror("application attribution unavailable");
            } else {
                app_resolver_set_debug(context.applications, context.debug_attribution);
                flow_set_application_resolver(context.flows, app_resolver_lookup, context.applications);
            }
        }
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

        context.current_info = info;
        context.automatic = source == NULL;

        uid_t owner = getuid();
        const char *sudo_uid = getenv("SUDO_UID");

        if (owner == 0 && sudo_uid != NULL && sudo_uid[0] != '\0') {
            char *end;
            const unsigned long value = strtoul(sudo_uid, &end, 10);

            if (*end == '\0' && value <= UINT32_MAX) {
                owner = (uid_t)value;
            }
        }

        context.control = control_server_open(database_path, owner);

        if (context.control == NULL) {
            perror("collector control unavailable");
            rc = -1;
        } else {
            struct capture_source *live = capture_source_open(info.name);

            rc = live == NULL ? -1 : 0;

            while (live != NULL) {
                rc = capture_source_run(live, observe_frame, tick_flows, &context);
                live = NULL;

                if (context.pending_source == NULL || rc == -1 || context.failed || capture_was_signalled()) {
                    break;
                }

                flow_destroy(context.flows);
                context.flows = context.pending_flows;
                context.pending_flows = NULL;
                context.local_count = context.pending_local_count;
                memcpy(context.locals, context.pending_locals, context.local_count * sizeof *context.locals);
                context.current_info = context.pending_info;
                context.automatic = context.pending_automatic;
                live = context.pending_source;
                context.pending_source = NULL;
                fprintf(stderr, "capture switched to %s (%s)\n", context.current_info.name,
                        context.automatic ? "automatic" : "manual");
            }
        }

        control_server_close(context.control);
        context.control = NULL;
        capture_source_close(context.pending_source);
        flow_destroy(context.pending_flows);
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
    app_resolver_destroy(context.applications);
    dns_cache_destroy(context.dns);
    store_close(context.store);

    return rc == 0 && !context.failed ? 0 : 1;
}
