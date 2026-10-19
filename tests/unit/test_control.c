#include "control/control.h"
#include "../t.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void respond(const char *request, char *reply, size_t capacity, void *user) {
    (void)user;
    CHECK(strcmp(request, "LIST") == 0);
    snprintf(reply, capacity, "OK\twifi0\tauto\nwifi0\tactive\tsupported\n");
}

static void exchange(struct control_server *server, const char *database, int authorized) {
    const pid_t child = fork();

    CHECK(child != -1);

    if (child == 0) {
        char reply[CONTROL_REPLY_LEN];

        CHECK(control_request(database, "LIST", reply, sizeof reply) == 0);
        CHECK(strncmp(reply, authorized ? "OK\t" : "ERROR\tNot authorized", authorized ? 3 : 20) == 0);
        _exit(0);
    }

    int status = 0;
    int finished = 0;

    for (int attempt = 0; attempt < 200 && !finished; attempt++) {
        control_server_poll(server, respond, NULL);
        finished = waitpid(child, &status, WNOHANG) == child;
        usleep(1000);
    }

    CHECK(finished && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
    char database[] = "/tmp/pigeon-control-XXXXXX";
    const int file = mkstemp(database);
    char path[CONTROL_PATH_LEN];

    CHECK(file != -1);
    close(file);
    CHECK(control_path(database, path) == 0);

    struct control_server *server = control_server_open(database, getuid());

    CHECK(server != NULL);
    CHECK(control_server_open(database, getuid()) == NULL && errno == EADDRINUSE);
    exchange(server, database, 1);
    control_server_close(server);
    CHECK(access(path, F_OK) == -1);

    /* An unrelated user cannot control the collector even though the socket
     * is writable. Root remains authorized by design. */
    if (getuid() != 0) {
        server = control_server_open(database, getuid() + 1);
        CHECK(server != NULL);
        exchange(server, database, 0);
        control_server_close(server);
    }

    /* Recover an owned socket left by a dead process. */
    const int stale = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un address = { .sun_family = AF_UNIX };

    strcpy(address.sun_path, path);
    CHECK(stale != -1 && bind(stale, (struct sockaddr *)&address, sizeof address) == 0);
    close(stale);
    server = control_server_open(database, getuid());
    CHECK(server != NULL);
    control_server_close(server);

    CHECK(symlink(database, path) == 0);
    CHECK(control_server_open(database, getuid()) == NULL && errno == EEXIST);
    CHECK(access(database, F_OK) == 0);
    unlink(path);

    char reply[32];

    CHECK(control_request(database, "LIST", reply, sizeof reply) == -1);
    unlink(database);

    return 0;
}
