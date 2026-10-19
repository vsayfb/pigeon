#include <fcntl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../t.h"
#include "store/store.h"
#include "dns/dns_cache.h"
#include <string.h>

static void run_replay(const char *program, const char *fixture, const char *database, const char *local) {
    const pid_t child = fork();

    CHECK(child != -1);

    if (child == 0) {
        const int output = open("/dev/null", O_WRONLY);

        if (output == -1 || dup2(output, STDOUT_FILENO) == -1) {
            _exit(126);
        }

        close(output);
        execl(program, program, "--local-ip", local, "--local-ip", "192.0.2.10", "--db", database,
              "-r", fixture, (char *)NULL);
        _exit(127);
    }

    int status;

    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status));
    CHECK(WEXITSTATUS(status) == 0);
}

static void test_named_replay(const char *program, const char *fixture) {
    char path[] = "/tmp/pigeon-dns-replay-XXXXXX";
    const int fd = mkstemp(path);

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    run_replay(program, fixture, path, "192.0.2.10");

    char error[STORE_ERROR_LEN];
    struct store *store = store_open(path, error);
    struct store_row row;

    const struct flow_key key = {
        .us_ip = ip_addr_v4(0xC000020A), .remote_ip = ip_addr_v4(0xC633642A),
        .remote_port = 443, .protocol = 17
    };

    CHECK(store != NULL);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 1);
    CHECK(row.delta.bytes_out == 1);
    CHECK(strcmp(row.remote_name, "www.example.test") == 0);

    struct dns_cache *cache = dns_cache_create(store, 8, 1700000003);

    CHECK(cache != NULL);
    CHECK(strcmp(dns_cache_lookup(cache, key.remote_ip, 1700000003), "www.example.test") == 0);

    dns_cache_destroy(cache);
    store_close(store);

    CHECK(unlink(path) == 0);
}

static void test_ipv6_replay(const char *program, const char *fixture) {
    char path[] = "/tmp/pigeon-ipv6-replay-XXXXXX";
    const int fd = mkstemp(path);

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    run_replay(program, fixture, path, "2001:db8::10");

    char error[STORE_ERROR_LEN];
    struct store *store = store_open(path, error);
    struct store_row row;
    struct flow_key key = { .remote_port = 443, .protocol = 6 };

    CHECK(store != NULL);
    CHECK(ip_addr_parse("2001:db8::10", &key.us_ip) == 0);
    CHECK(ip_addr_parse("2001:db8:1::42", &key.remote_ip) == 0);
    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 2);
    CHECK(row.delta.packets_in == 1);
    CHECK(row.delta.bytes_out == 15);
    CHECK(row.delta.bytes_in == 6);
    CHECK(strcmp(row.remote_name, "www.v6.example.test") == 0);

    key.protocol = 17;

    CHECK(store_lookup(store, &key, &row) == 1);
    CHECK(row.delta.packets_out == 1);
    CHECK(row.delta.bytes_out == 1);
    CHECK(strcmp(row.remote_name, "www.v6.example.test") == 0);

    struct dns_cache *cache = dns_cache_create(store, 8, 1700000006);

    CHECK(cache != NULL);
    CHECK(strcmp(dns_cache_lookup(cache, key.remote_ip, 1700000006), "www.v6.example.test") == 0);

    dns_cache_destroy(cache);
    store_close(store);

    CHECK(unlink(path) == 0);
}

int main(int argc, char **argv) {
    CHECK(argc == 6);

    test_ipv6_replay(argv[1], argv[5]);

    test_named_replay(argv[1], argv[3]);
    test_named_replay(argv[1], argv[4]);

    char path[] = "/tmp/pigeon-replay-XXXXXX";
    const int fd = mkstemp(path);

    CHECK(fd != -1);
    CHECK(close(fd) == 0);

    for (unsigned run = 1; run <= 2; run++) {
        run_replay(argv[1], argv[2], path, "192.0.2.10");

        char error[STORE_ERROR_LEN];
        struct store *store = store_open(path, error);
        struct store_row row;
        struct flow_key key = {
            .us_ip = ip_addr_v4(0xC000020A), .remote_ip = ip_addr_v4(0xC6336414),
            .remote_port = 80, .protocol = 6
        };

        CHECK(store != NULL);
        CHECK(store_lookup(store, &key, &row) == 1);
        CHECK(row.delta.packets_out == 2 * run);
        CHECK(row.delta.packets_in == run);
        CHECK(row.delta.bytes_out == run);
        CHECK(row.delta.bytes_in == 0);
        CHECK(row.delta.first_seen == 1700000000);
        CHECK(row.delta.last_seen == 1700000000);

        key.remote_port = 9999;
        key.protocol = 17;

        CHECK(store_lookup(store, &key, &row) == 1);
        CHECK(row.delta.packets_out == run);
        CHECK(row.delta.packets_in == 0);
        CHECK(row.delta.bytes_out == run);
        CHECK(row.delta.bytes_in == 0);

        store_close(store);
    }

    CHECK(unlink(path) == 0);

    puts("replay_store: ok");

    return 0;
}
