#include "../t.h"
#include "flow/flow.h"
#include "store/store.h"
#include "dns/dns_cache.h"
#include <sqlite3.h>
#include <unistd.h>

static void pending_owner(const struct flow_key *key, uint16_t port, char name[FLOW_APP_LEN], void *user) {
    (void)key;
    (void)port;
    (void)user;
    name[0] = '\0';
}

static int count_dns(const struct store_dns_row *row, void *user) {
    (void)row;
    (*(int *)user)++;

    return 0;
}

int main(void) {
    char error[STORE_ERROR_LEN];
    char database[] = "/tmp/pigeon-history-XXXXXX";
    const int fd = mkstemp(database);
    CHECK(fd != -1);
    close(fd);
    struct store *store = store_open(database, error);
    CHECK(store != NULL);
    struct flow *flow = flow_create(0xc000020a, 16, 100);
    CHECK(flow != NULL);
    flow_set_store(flow, store);
    struct dns_cache *dns = dns_cache_create(store, 100, 100);
    CHECK(dns != NULL);
    flow_set_dns_cache(flow, dns);
    struct packet_view packet = { .kind = PACKET_UDP };
    packet.ip.src = 0xc000020a;
    packet.ip.dst = 0xc6336414;
    packet.ip.protocol = 17;
    packet.transport.udp.src_port = 12345;
    packet.transport.udp.dst_port = 443;
    packet.transport.udp.payload_wire_len = 7;
    CHECK(flow_observe(flow, &packet, 100) == 1);
    packet.transport.udp.dst_port = 80;
    CHECK(flow_observe(flow, &packet, 100) == 1);
    struct flow_key first = { .us_ip = ip_addr_v4(0xc000020a), .remote_ip = ip_addr_v4(0xc6336414), .remote_port = 443, .protocol = 17 };
    struct flow_key second = first;
    second.remote_port = 80;
    struct store_row row;
    CHECK(flow_delete(flow, &first) == 0);
    CHECK(flow_find(flow, &first) == NULL && flow_count(flow) == 1);
    CHECK(store_lookup(store, &first, &row) == 0);
    CHECK(store_lookup(store, &second, &row) == 1 && row.delta.bytes_out == 7);
    CHECK(flow_flush(flow) == 0 && store_lookup(store, &first, &row) == 0);
    packet.transport.udp.dst_port = 443;
    packet.transport.udp.payload_wire_len = 2;
    CHECK(flow_observe(flow, &packet, 200) == 1);
    CHECK(flow_flush(flow) == 0);
    CHECK(store_lookup(store, &first, &row) == 1 && row.delta.bytes_out == 2 && row.delta.first_seen == 200);

    struct store_dns_row name = { .ip = first.remote_ip, .observed_at = 100, .expires_at = 1000 };
    strcpy(name.name, "example.test");
    CHECK(store_dns_save(store, &name) == 1);
    struct dns_answer answer = { .ip = first.remote_ip, .ttl = 900 };
    strcpy(answer.name, "example.test");
    CHECK(dns_cache_update(dns, &answer, 100) == 1);
    CHECK(dns_cache_lookup(dns, first.remote_ip, 200) != NULL);
    flow_set_application_resolver(flow, pending_owner, NULL);
    CHECK(flow_observe(flow, &packet, 201) == 1 && flow_pending_count(flow) == 1);
    CHECK(flow_delete(flow, NULL) == 0);
    CHECK(flow_count(flow) == 0 && flow_pending_count(flow) == 0);
    CHECK(dns_cache_lookup(dns, first.remote_ip, 200) == NULL);
    CHECK(flow_flush(flow) == 0 && store_lookup(store, &first, &row) == 0);
    CHECK(store_lookup(store, &second, &row) == 0);
    int names = 0;
    CHECK(store_dns_load(store, 200, count_dns, &names) == 0 && names == 0);

    struct flow_key decoded;
    CHECK(flow_key_decode("04c000020a04c633641401bb11", &decoded) == 0);
    CHECK(flow_key_equal(&first, &decoded));
    CHECK(flow_key_decode("04c000020a04c633641401bb116368726f6d65", &decoded) == 0);
    CHECK(strcmp(decoded.application, "chrome") == 0);
    CHECK(flow_key_decode("04c000020a04c633641401bb1100", &decoded) == -1);
    CHECK(flow_key_decode("04c000020a04c633641401bb1z", &decoded) == -1);
    CHECK(flow_key_decode("10c000020a04c633641401bb11", &decoded) == -1);

    struct store_row processes[2] = { { .key = first }, { .key = first } };
    strcpy(processes[0].key.application, "chrome");
    strcpy(processes[1].key.application, "firefox");
    CHECK(store_flush(store, processes, 2) == 0);
    CHECK(store_delete(store, &processes[0].key) == 0);
    CHECK(store_lookup(store, &processes[0].key, &row) == 0);
    CHECK(store_lookup(store, &processes[1].key, &row) == 1);

    sqlite3 *external = NULL;
    CHECK(sqlite3_open(database, &external) == SQLITE_OK);
    CHECK(sqlite3_exec(external, "CREATE TRIGGER deny_history_delete BEFORE DELETE ON conversations "
                      "BEGIN SELECT RAISE(ABORT,'blocked'); END", NULL, NULL, NULL) == SQLITE_OK);
    flow_set_application_resolver(flow, NULL, NULL);
    CHECK(flow_observe(flow, &packet, 300) == 1);
    CHECK(flow_delete(flow, NULL) == -1);
    CHECK(flow_count(flow) == 1);
    CHECK(store_lookup(store, &processes[1].key, &row) == 1);
    CHECK(sqlite3_exec(external, "DROP TRIGGER deny_history_delete", NULL, NULL, NULL) == SQLITE_OK);
    sqlite3_close(external);
    CHECK(flow_delete(flow, NULL) == 0);

    flow_destroy(flow);
    dns_cache_destroy(dns);
    store_close(store);
    unlink(database);
    puts("history: deletion does not resurrect counters; new traffic starts fresh; process keys stay separate");

    return 0;
}
