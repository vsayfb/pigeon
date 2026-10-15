#include "capture/capture.h"

#include <pcap/pcap.h>
#include <stdio.h>

/* Context handed to libpcap: the caller's callback and its user pointer. */
struct trampoline {
    capture_cb cb;
    void *user;
};

/* libpcap handler; forwards each packet to the caller's callback. */
static void on_pcap_packet(u_char *arg, const struct pcap_pkthdr *hdr,
                           const u_char *bytes) {
    struct trampoline *t = (struct trampoline *)arg;

    t->cb(bytes, hdr->caplen, hdr->len, t->user);
}

int capture_run_live(const char *ifname, capture_cb cb, void *user) {
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Full-size snapshots, non-promiscuous, 1 s read timeout. */
    pcap_t *handle = pcap_open_live(ifname, 65535, 0, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", ifname, errbuf);

        return -1;
    }

    struct trampoline t = { .cb = cb, .user = user };

    const int rc = pcap_loop(handle, -1, on_pcap_packet, (u_char *)&t);

    if (rc == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);

    return rc == PCAP_ERROR ? -1 : 0;
}