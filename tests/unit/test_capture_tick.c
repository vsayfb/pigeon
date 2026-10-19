#include <pcap/pcap.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include "../t.h"
#include "capture/capture.h"

static int fake_handle;
static unsigned polls;
static unsigned ticks;
static unsigned breaks;
static unsigned closes;
static int signal_to_raise;
static unsigned dispatches;
static unsigned error_reads;
static short poll_events;
static int backend_result;
static int stop_during_poll;
static int poll_errno;
static int nonblock_failure;
static int selectable_fd = 42;

pcap_t *__wrap_pcap_open_live(const char *name, int snaplen, int promiscuous,
                              int timeout, char *error) {
    (void)name;
    (void)snaplen;
    (void)promiscuous;
    (void)timeout;
    (void)error;

    return (pcap_t *)&fake_handle;
}

int __wrap_pcap_datalink(pcap_t *handle) {
    (void)handle;

    return DLT_EN10MB;
}

int __wrap_pcap_get_selectable_fd(pcap_t *handle) {
    (void)handle;

    return selectable_fd;
}

int __wrap_pcap_setnonblock(pcap_t *handle, int enabled, char *error) {
    (void)handle;
    (void)error;

    CHECK(enabled == 1);

    if (nonblock_failure) {
        strcpy(error, "nonblocking setup failed");

        return -1;
    }

    return 0;
}

int __wrap_pcap_dispatch(pcap_t *handle, int count, pcap_handler callback, u_char *user) {
    (void)handle;
    (void)callback;
    (void)user;

    CHECK(count == 64);
    dispatches++;

    return polls != 0 ? backend_result : 0;
}

char *__wrap_pcap_geterr(pcap_t *handle) {
    (void)handle;

    error_reads++;

    return "interface went down";
}

void __wrap_pcap_breakloop(pcap_t *handle) {
    (void)handle;

    breaks++;
}

void __wrap_pcap_close(pcap_t *handle) {
    (void)handle;

    closes++;
}

int __wrap_poll(struct pollfd *descriptors, nfds_t count, int timeout) {
    CHECK(count == 1);
    CHECK(descriptors[0].fd == 42);
    CHECK(descriptors[0].events == POLLIN);
    CHECK(timeout == 1000);

    descriptors[0].revents = poll_events;
    polls++;

    if (stop_during_poll) {
        CHECK(raise(SIGTERM) == 0);
    }

    if (poll_errno != 0) {
        errno = poll_errno;

        return -1;
    }

    return poll_events != 0 ? 1 : 0;
}

time_t __wrap_time(time_t *out) {
    const time_t now = 100 + polls;

    if (out != NULL) {
        *out = now;
    }

    return now;
}

static void no_packets(const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                        int64_t timestamp, void *user) {
    (void)data;
    (void)caplen;
    (void)wirelen;
    (void)timestamp;
    (void)user;

    CHECK(0);
}

static void idle_tick(int64_t now, void *user) {
    CHECK(user == &fake_handle);
    CHECK(now == 100 + (int64_t)ticks);

    ticks++;

    if (ticks == 3) {
        if (signal_to_raise != 0) {
            CHECK(raise(signal_to_raise) == 0);
        } else {
            capture_stop();
        }
    }
}

static void test_idle_stop(int signo) {
    struct sigaction before_int;
    struct sigaction before_term;
    struct sigaction after_int;
    struct sigaction after_term;

    CHECK(sigaction(SIGINT, NULL, &before_int) == 0);
    CHECK(sigaction(SIGTERM, NULL, &before_term) == 0);

    polls = ticks = breaks = closes = 0;
    signal_to_raise = signo;

    CHECK(capture_run_live_tick("fake", no_packets, idle_tick, &fake_handle) == 0);
    CHECK(ticks == 3);
    CHECK(polls == 2);
    CHECK(breaks == 1);
    CHECK(closes == 1);
    CHECK(sigaction(SIGINT, NULL, &after_int) == 0);
    CHECK(sigaction(SIGTERM, NULL, &after_term) == 0);
    CHECK(before_int.sa_handler == after_int.sa_handler);
    CHECK(before_term.sa_handler == after_term.sa_handler);
}

static void reset_case(void) {
    polls = ticks = breaks = closes = dispatches = error_reads = 0;
    signal_to_raise = poll_events = backend_result = stop_during_poll = poll_errno = nonblock_failure = 0;
    selectable_fd = 42;
}

static void run_with_error(char error[512], int *result) {
    FILE *stream = tmpfile();
    const int previous = dup(STDERR_FILENO);

    CHECK(stream != NULL && previous != -1);
    CHECK(fflush(stderr) == 0);
    CHECK(dup2(fileno(stream), STDERR_FILENO) != -1);

    *result = capture_run_live_tick("fake", no_packets, idle_tick, &fake_handle);

    CHECK(fflush(stderr) == 0);
    CHECK(dup2(previous, STDERR_FILENO) != -1);
    CHECK(close(previous) == 0);
    rewind(stream);

    const size_t length = fread(error, 1, 511, stream);

    error[length] = '\0';
    CHECK(fclose(stream) == 0);
}

static void test_poll_errors(void) {
    const short events[] = { POLLERR, POLLHUP, POLLNVAL, POLLIN | POLLERR };

    for (size_t i = 0; i < sizeof events / sizeof events[0]; i++) {
        char error[512];
        int result;

        reset_case();
        poll_events = events[i];
        run_with_error(error, &result);
        CHECK(result == -1);
        CHECK(closes == 1 && error_reads == 0);
        CHECK(dispatches == (events[i] & POLLNVAL ? 1 : 2));
        CHECK(strstr(error, "capture poll: fd=42 revents=0x") != NULL);
        CHECK(strstr(error, "pcap_loop") == NULL);
        CHECK(strstr(error, "pcap_dispatch") == NULL);
    }
}

static void test_backend_error_after_poll(void) {
    char error[512];
    int result;

    reset_case();
    poll_events = POLLERR;
    backend_result = PCAP_ERROR;
    run_with_error(error, &result);
    CHECK(result == -1);
    CHECK(error_reads == 1 && closes == 1 && dispatches == 2);
    CHECK(strcmp(error, "pcap_dispatch: interface went down\n") == 0);

    reset_case();
    poll_events = POLLHUP;
    stop_during_poll = 1;
    run_with_error(error, &result);
    CHECK(result == 0);
    CHECK(error_reads == 0 && closes == 1 && dispatches == 1);
    CHECK(error[0] == '\0');
}

static void test_local_setup_and_poll_failures(void) {
    char error[512];
    int result;

    reset_case();
    nonblock_failure = 1;
    run_with_error(error, &result);
    CHECK(result == -1 && closes == 1 && error_reads == 0);
    CHECK(strcmp(error, "pcap_setnonblock: nonblocking setup failed\n") == 0);

    reset_case();
    selectable_fd = -1;
    run_with_error(error, &result);
    CHECK(result == -1 && closes == 1 && error_reads == 0);
    CHECK(strcmp(error, "capture has no selectable descriptor\n") == 0);

    reset_case();
    poll_errno = EIO;
    run_with_error(error, &result);
    CHECK(result == -1 && closes == 1 && error_reads == 0);
    CHECK(strstr(error, "capture poll:") != NULL);
    CHECK(strstr(error, "pcap_loop") == NULL);

    reset_case();
    poll_errno = EINTR;
    run_with_error(error, &result);
    CHECK(result == 0 && ticks == 3 && closes == 1);
    CHECK(error[0] == '\0');
}

int main(void) {
    test_idle_stop(0);
    test_idle_stop(SIGINT);
    test_idle_stop(SIGTERM);
    test_poll_errors();
    test_backend_error_after_poll();
    test_local_setup_and_poll_failures();

    puts("capture_tick: ok");

    return 0;
}
