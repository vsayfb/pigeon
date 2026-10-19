#include "capture/capture.h"

#include <errno.h>
#include <poll.h>
#include <time.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

/* Context handed to libpcap: the caller's callback and its user pointer. */
struct trampoline {
    capture_cb cb;
    void *user;
};

/* Handle of the running capture, or NULL. Read by the signal handler. */
static pcap_t *volatile active_handle;
static volatile sig_atomic_t stop_requested;

/* libpcap handler; forwards each packet to the caller's callback. */
static void on_pcap_packet(u_char *arg, const struct pcap_pkthdr *hdr,
                           const u_char *bytes) {
    struct trampoline *t = (struct trampoline *)arg;

    t->cb(bytes, hdr->caplen, hdr->len, (int64_t)hdr->ts.tv_sec, t->user);
}

/* Signal handler for SIGINT/SIGTERM; makes pcap_loop() return. */
static void on_stop_signal(int signo) {
    (void)signo;

    stop_requested = 1;

    pcap_t *handle = active_handle;

    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

/* Installs on_stop_signal for `signo`, saving the previous action in `old`. */
static int install_stop_handler(int signo, struct sigaction *old) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_stop_signal;
    sigemptyset(&sa.sa_mask);

    return sigaction(signo, &sa, old);
}

static int run_live_ticks(pcap_t *handle, struct trampoline *context,
                           capture_tick_cb tick) {
    char error[PCAP_ERRBUF_SIZE];
    const int fd = pcap_get_selectable_fd(handle);

    if (fd == -1 || pcap_setnonblock(handle, 1, error) == -1) {
        fprintf(stderr, "capture requires a selectable nonblocking descriptor\n");

        return PCAP_ERROR;
    }

    struct pollfd descriptor = { .fd = fd, .events = POLLIN };

    while (!stop_requested) {
        const int count = pcap_dispatch(handle, 64, on_pcap_packet, (u_char *)context);

        if (count < 0) {
            return count;
        }

        if (stop_requested) {
            break;
        }

        const time_t now = time(NULL);

        if (now == (time_t)-1) {
            perror("capture clock");

            return PCAP_ERROR;
        }

        tick((int64_t)now, context->user);

        if (count == 0 && !stop_requested) {
            const int ready = poll(&descriptor, 1, 1000);

            if (ready == -1 && errno != EINTR) {
                perror("capture poll");

                return PCAP_ERROR;
            }

            if (ready > 0 && (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL))) {
                fprintf(stderr, "capture descriptor failed\n");

                return PCAP_ERROR;
            }
        }
    }

    return 0;
}

/* Delivers packets from `handle` to `cb` until the source ends, then
 * closes the handle. Returns 0 on normal end, -1 on error. */
static int run_loop(pcap_t *handle, capture_cb cb, capture_tick_cb tick, void *user) {

    const int linktype = pcap_datalink(handle);

    if (linktype != DLT_EN10MB) {
        fprintf(stderr, "unsupported link type %d: only Ethernet is handled\n",
                linktype);
        pcap_close(handle);

        return -1;
    }

    struct sigaction old_int;
    struct sigaction old_term;

    /* Set before installing handlers so no signal can arrive unseen. */
    stop_requested = 0;
    active_handle = handle;

    if (install_stop_handler(SIGINT, &old_int) == -1) {
        perror("sigaction(SIGINT)");
        active_handle = NULL;
        pcap_close(handle);

        return -1;
    }

    if (install_stop_handler(SIGTERM, &old_term) == -1) {
        perror("sigaction(SIGTERM)");
        sigaction(SIGINT, &old_int, NULL);
        active_handle = NULL;
        pcap_close(handle);

        return -1;
    }

    struct trampoline t = { .cb = cb, .user = user };

    /* Returns PCAP_ERROR_BREAK when stopped by on_stop_signal(). */
    const int rc = tick == NULL ? pcap_loop(handle, -1, on_pcap_packet, (u_char *)&t)
                               : run_live_ticks(handle, &t, tick);

    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGTERM, &old_term, NULL);
    active_handle = NULL;

    if (rc == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);

    return rc == PCAP_ERROR ? -1 : 0;
}


int capture_run_live_tick(const char *ifname, capture_cb cb, capture_tick_cb tick, void *user) {
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Full-size snapshots, non-promiscuous, 1 s read timeout. */
    pcap_t *handle = pcap_open_live(ifname, 65535, 0, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", ifname, errbuf);

        return -1;
    }

    return run_loop(handle, cb, tick, user);
}

int capture_run_file(const char *path, capture_cb cb, void *user) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_offline(path, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_offline(%s): %s\n", path, errbuf);

        return -1;
    }

    return run_loop(handle, cb, NULL, user);
}

void capture_stop(void) {
    stop_requested = 1;

    pcap_t *handle = active_handle;

    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

int capture_run_live(const char *ifname, capture_cb cb, void *user) {
    return capture_run_live_tick(ifname, cb, NULL, user);
}
