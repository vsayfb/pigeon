#include <pcap/pcap.h>
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

    return 42;
}

int __wrap_pcap_setnonblock(pcap_t *handle, int enabled, char *error) {
    (void)handle;
    (void)error;

    CHECK(enabled == 1);

    return 0;
}

int __wrap_pcap_dispatch(pcap_t *handle, int count, pcap_handler callback, u_char *user) {
    (void)handle;
    (void)callback;
    (void)user;

    CHECK(count == 64);

    return 0;
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

    descriptors[0].revents = 0;
    polls++;

    return 0;
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

int main(void) {
    test_idle_stop(0);
    test_idle_stop(SIGINT);
    test_idle_stop(SIGTERM);

    puts("capture_tick: ok");

    return 0;
}
