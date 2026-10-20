#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../t.h"
#include "app/app_internal.h"

static atomic_uint samples;

struct app_snapshot *__wrap_app_snapshot_read(void) {
    struct app_snapshot *snapshot = calloc(1, sizeof *snapshot);

    CHECK(snapshot != NULL);
    snapshot->sockets = calloc(1, sizeof *snapshot->sockets);
    CHECK(snapshot->sockets != NULL);
    snapshot->count = 1;
    snapshot->sockets[0] = (struct app_socket){
        .local = ip_addr_v4(0xc000020a), .remote = ip_addr_v4(0xc633642a),
        .local_port = 50000, .remote_port = 443, .protocol = 6,
        .inode = 42, .cookie = 99, .cookie_valid = 1
    };

    if (atomic_load(&samples) == 0) {
        strcpy(snapshot->sockets[0].application, "brave");
        snapshot->sockets[0].owner_seen = 1;
    }

    atomic_fetch_add(&samples, 1);

    return snapshot;
}

int main(void) {
    struct app_resolver *resolver = app_resolver_create();
    struct flow_key key = { .us_ip = ip_addr_v4(0xc000020a), .remote_ip = ip_addr_v4(0xc633642a),
                            .remote_port = 443, .protocol = 6 };
    char application[FLOW_APP_LEN];

    CHECK(resolver != NULL);

    for (int attempt = 0; attempt < 1000; attempt++) {
        app_resolver_lookup(&key, 50000, application, resolver);

        if (application[0] != '\0') {
            break;
        }

        usleep(1000);
    }

    CHECK(strcmp(application, "brave") == 0);

    FILE *log = tmpfile();
    const int previous = dup(STDERR_FILENO);

    CHECK(log != NULL && previous != -1);
    CHECK(fflush(stderr) == 0 && dup2(fileno(log), STDERR_FILENO) != -1);
    app_resolver_set_debug(resolver, 1);

    for (unsigned i = 0; i < 100; i++) {
        app_resolver_lookup(&key, 50000, application, resolver);
    }

    for (unsigned i = 0; i < 100; i++) {
        app_resolver_lookup(&key, (uint16_t)(51000 + i), application, resolver);
    }

    /* The next background sample misses /proc ownership for the same socket. */
    for (unsigned attempt = 0; attempt < 2000 && atomic_load(&samples) < 2; attempt++) {
        usleep(1000);
    }

    CHECK(atomic_load(&samples) >= 2);
    usleep(10000);
    app_resolver_lookup(&key, 50000, application, resolver);
    CHECK(strcmp(application, "brave") == 0);
    app_resolver_set_debug(resolver, 0);
    CHECK(fflush(stderr) == 0 && dup2(previous, STDERR_FILENO) != -1);
    close(previous);
    rewind(log);

    char contents[32768];
    const size_t length = fread(contents, 1, sizeof contents - 1, log);

    contents[length] = '\0';
    CHECK(strstr(contents, "local=[192.0.2.10]:50000") != NULL);
    CHECK(strstr(contents, "peer=[198.51.100.42]:443") != NULL);
    CHECK(strstr(contents, "owner=brave result=snapshot") != NULL);
    CHECK(strstr(contents, "owner=brave result=cache") != NULL);
    CHECK(strstr(contents, "result=no-matching-socket") != NULL);
    CHECK(strstr(contents, "attribution rate-limited=") != NULL);

    unsigned lines = 0;

    for (size_t i = 0; i < length; i++) {
        lines += contents[i] == '\n';
    }

    CHECK(lines < 45);
    fclose(log);
    app_resolver_destroy(resolver);

    return 0;
}
