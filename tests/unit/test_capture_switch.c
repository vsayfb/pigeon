#define main pigeon_cli_main
#include "../../src/main.c"
#undef main

#include "../t.h"

#include <sys/wait.h>

static int fake_source;
static int fail_open;
static int stopped;
static int closed;

int __wrap_netif_select(const char *name, struct netif_info *out) {
    memset(out, 0, sizeof *out);
    snprintf(out->name, sizeof out->name, "%s", name == NULL ? "eth0" : name);

    return 0;
}

int __wrap_netif_addresses(const char *name, struct ip_addr *out, size_t capacity, size_t *count) {
    (void)name;
    CHECK(capacity == 64);
    out[0] = ip_addr_v4(0xc000020b);
    *count = 1;

    return 0;
}

int __wrap_capture_select_interface(const char *preferred, int explicit_selection, char *out, size_t capacity) {
    (void)explicit_selection;

    if (strcmp(preferred, "bad0") == 0) {
        return -1;
    }

    snprintf(out, capacity, "%s", preferred);

    return 0;
}

struct capture_source *__wrap_capture_source_open(const char *name) {
    CHECK(strcmp(name, "eth0") == 0);

    return fail_open ? NULL : (struct capture_source *)&fake_source;
}

void __wrap_capture_source_close(struct capture_source *source) {
    if (source != NULL) {
        CHECK(source == (struct capture_source *)&fake_source);
        closed++;
    }
}

void __wrap_capture_stop(void) {
    stopped++;
}

int main(void) {
    const pid_t original_session = getsid(0);
    const int detached = detach_capture();

    CHECK(detached != -1);

    if (detached == 0) {
        CHECK(getsid(0) == getpid() && getsid(0) != original_session);
        _exit(0);
    }

    int child_status;

    CHECK(wait(&child_status) > 0);
    CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);

    struct capture_context context = { 0 };
    char error[STORE_ERROR_LEN];
    char reply[1024];

    context.store = store_open(":memory:", error);
    CHECK(context.store != NULL);
    context.flows = flow_create(0xc000020a, 16, 100);
    CHECK(context.flows != NULL);
    flow_set_store(context.flows, context.store);
    strcpy(context.current_info.name, "wifi0");

    struct packet_view packet = { .kind = PACKET_UDP };

    packet.ip.src = 0xc000020a;
    packet.ip.dst = 0xc6336414;
    packet.ip.protocol = 17;
    packet.transport.udp.src_port = 12345;
    packet.transport.udp.dst_port = 443;
    packet.transport.udp.payload_wire_len = 7;
    CHECK(flow_observe(context.flows, &packet, 100) == 1);

    control_command("SELECT bad0", reply, sizeof reply, &context);
    CHECK(strncmp(reply, "ERROR", 5) == 0 && !stopped && context.pending_source == NULL);
    fail_open = 1;
    control_command("SELECT eth0", reply, sizeof reply, &context);
    CHECK(strncmp(reply, "ERROR", 5) == 0 && !stopped);
    fail_open = 0;
    flow_set_store(context.flows, NULL);
    control_command("SELECT eth0", reply, sizeof reply, &context);
    CHECK(strncmp(reply, "ERROR", 5) == 0 && !stopped && closed == 1);
    flow_set_store(context.flows, context.store);

    control_command("SELECT wifi0", reply, sizeof reply, &context);
    CHECK(strncmp(reply, "OK\twifi0\tmanual", 15) == 0 && !stopped);
    control_command("STATUS", reply, sizeof reply, &context);
    CHECK(strcmp(reply, "OK\twifi0\tmanual\n") == 0 && !stopped);
    control_command("INVALID", reply, sizeof reply, &context);
    CHECK(strncmp(reply, "ERROR", 5) == 0);
    control_command("AUTO", reply, sizeof reply, &context);
    CHECK(strncmp(reply, "OK\teth0\tauto", 12) == 0 && stopped == 1);
    CHECK(context.pending_source != NULL && context.pending_flows != NULL);
    CHECK(context.pending_automatic && context.pending_local_count == 1);
    CHECK(strcmp(context.current_info.name, "wifi0") == 0);

    const struct flow_key key = {
        .us_ip = ip_addr_v4(0xc000020a), .remote_ip = ip_addr_v4(0xc6336414),
        .remote_port = 443, .protocol = 17
    };
    struct store_row row;

    CHECK(store_lookup(context.store, &key, &row) == 1 && row.delta.bytes_out == 7);
    CHECK(flow_flush(context.flows) == 0);
    CHECK(store_lookup(context.store, &key, &row) == 1 && row.delta.bytes_out == 7);

    control_command("STOP", reply, sizeof reply, &context);
    CHECK(strcmp(reply, "OK\tStopping\n") == 0);
    CHECK(context.shutdown_requested && stopped == 2);

    capture_source_close(context.pending_source);
    flow_destroy(context.pending_flows);
    flow_destroy(context.flows);
    store_close(context.store);

    return 0;
}
