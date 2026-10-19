#include <pcap/pcap.h>
#include <string.h>
#include <sys/socket.h>

#include "../t.h"
#include "capture/capture.h"

static struct sockaddr ip = { .sa_family = AF_INET };
static pcap_addr_t address = { .addr = &ip };
static pcap_if_t devices[5];
static int handle;
static int opened;
static int closes;
static int frees;
static int discovery_failure;
static int denied;
static int no_descriptor;

int __wrap_pcap_findalldevs(pcap_if_t **out, char *error) {
    if (discovery_failure) {
        strcpy(error, "discovery failed");

        return -1;
    }

    *out = devices;

    return 0;
}

void __wrap_pcap_freealldevs(pcap_if_t *list) {
    CHECK(list == devices);
    frees++;
}

pcap_t *__wrap_pcap_open_live(const char *name, int snaplen, int promisc, int timeout, char *error) {
    CHECK(snaplen == 65535 && promisc == 0 && timeout == 1000);
    opened++;

    if (denied) {
        strcpy(error, "permission denied");

        return NULL;
    }

    handle = strcmp(name, "tun0") == 0 ? DLT_RAW : DLT_EN10MB;

    return (pcap_t *)&handle;
}

int __wrap_pcap_datalink(pcap_t *capture) {
    CHECK(capture == (pcap_t *)&handle);

    return handle;
}

int __wrap_pcap_get_selectable_fd(pcap_t *capture) {
    (void)capture;

    return no_descriptor ? -1 : 12;
}

void __wrap_pcap_close(pcap_t *capture) {
    CHECK(capture == (pcap_t *)&handle);
    closes++;
}

int main(void) {
    char selected[16] = "unchanged";
    char *names[] = { "down0", "lo", "noip0", "tun0", "wifi0" };

    for (int i = 0; i < 5; i++) {
        devices[i].name = names[i];
        devices[i].flags = PCAP_IF_UP | PCAP_IF_RUNNING;
        devices[i].addresses = &address;
        devices[i].next = i == 4 ? NULL : &devices[i + 1];
    }

    devices[0].flags = 0;
    devices[1].flags |= PCAP_IF_LOOPBACK;
    devices[2].addresses = NULL;

    CHECK(capture_select_interface("wifi0", 0, selected, sizeof selected) == 0);
    CHECK(strcmp(selected, "wifi0") == 0 && opened == 1 && closes == 1);
    CHECK(capture_select_interface("tun0", 0, selected, sizeof selected) == 0);
    CHECK(strcmp(selected, "wifi0") == 0 && opened == 3 && closes == 3);
    CHECK(capture_select_interface(NULL, 0, selected, sizeof selected) == 0);
    CHECK(strcmp(selected, "wifi0") == 0);

    strcpy(selected, "unchanged");
    CHECK(capture_select_interface("tun0", 1, selected, sizeof selected) == -1);
    CHECK(strcmp(selected, "unchanged") == 0);
    CHECK(capture_select_interface("wifi0", 1, selected, sizeof selected) == 0);
    CHECK(capture_select_interface("wifi0", 1, selected, 2) == -1);

    denied = 1;
    strcpy(selected, "unchanged");
    CHECK(capture_select_interface(NULL, 0, selected, sizeof selected) == -1);
    CHECK(strcmp(selected, "unchanged") == 0);
    denied = 0;
    no_descriptor = 1;
    CHECK(capture_select_interface(NULL, 0, selected, sizeof selected) == -1);
    no_descriptor = 0;

#ifdef PCAP_IF_CONNECTION_STATUS
    devices[4].flags |= PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
    CHECK(capture_select_interface(NULL, 0, selected, sizeof selected) == -1);
#endif

    CHECK(frees == 5
#ifdef PCAP_IF_CONNECTION_STATUS
          + 1
#endif
    );

    discovery_failure = 1;
    CHECK(capture_select_interface(NULL, 0, selected, sizeof selected) == -1);

    return 0;
}
