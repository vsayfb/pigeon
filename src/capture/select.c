#include "capture/capture.h"

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <net/if.h>

static int active_ip_interface(const pcap_if_t *device) {
    const unsigned required = PCAP_IF_UP | PCAP_IF_RUNNING;

    if ((device->flags & required) != required || (device->flags & PCAP_IF_LOOPBACK)) {
        return 0;
    }

#ifdef PCAP_IF_CONNECTION_STATUS
    if ((device->flags & PCAP_IF_CONNECTION_STATUS) == PCAP_IF_CONNECTION_STATUS_DISCONNECTED) {
        return 0;
    }
#endif

    for (const pcap_addr_t *address = device->addresses; address != NULL; address = address->next) {
        if (address->addr != NULL &&
            (address->addr->sa_family == AF_INET || address->addr->sa_family == AF_INET6)) {
            return 1;
        }
    }

    return 0;
}

static int probe_interface(const char *name) {
    char error[PCAP_ERRBUF_SIZE] = "";
    pcap_t *handle = pcap_open_live(name, 65535, 0, 1000, error);

    if (handle == NULL) {
        fprintf(stderr, "interface %s unavailable: %s\n", name, error);

        return 0;
    }

    const int linktype = pcap_datalink(handle);
    const int selectable = pcap_get_selectable_fd(handle) != -1;

    pcap_close(handle);

    if (linktype != DLT_EN10MB) {
        fprintf(stderr, "skipping interface %s: unsupported capture link type %d\n", name, linktype);

        return 0;
    }

    if (!selectable) {
        fprintf(stderr, "skipping interface %s: no selectable capture descriptor\n", name);

        return 0;
    }

    return 1;
}

int capture_select_interface(const char *preferred, int explicit_selection,
                             char *out, size_t capacity) {
    char error[PCAP_ERRBUF_SIZE] = "";
    pcap_if_t *devices = NULL;

    if (explicit_selection) {
        if (preferred == NULL || strlen(preferred) >= capacity) {
            fprintf(stderr, "invalid capture interface name\n");

            return -1;
        }

        if (!probe_interface(preferred)) {
            return -1;
        }

        memcpy(out, preferred, strlen(preferred) + 1);

        return 0;
    }

    if (pcap_findalldevs(&devices, error) == -1) {
        fprintf(stderr, "interface discovery: %s\n", error);

        return -1;
    }

    int result = -1;

    /* Try the routed interface first, then remaining active IP interfaces. */
    for (int pass = 0; pass < 2 && result == -1; pass++) {
        for (const pcap_if_t *device = devices; device != NULL; device = device->next) {
            const int preferred_device = preferred != NULL && strcmp(device->name, preferred) == 0;

            if ((pass == 0) != preferred_device || !active_ip_interface(device) ||
                strlen(device->name) >= capacity || !probe_interface(device->name)) {
                continue;
            }

            memcpy(out, device->name, strlen(device->name) + 1);
            result = 0;

            if (pass == 1) {
                fprintf(stderr, "using active supported interface %s%s\n", device->name,
                        preferred != NULL ? " (route-selected interface unavailable or unsupported)" : "");
            }

            break;
        }
    }

    pcap_freealldevs(devices);

    if (result == -1) {
        fprintf(stderr, "no active supported IP capture interface available; check capture privileges\n");
    }

    return result;
}

int capture_interface_list(char *out, size_t capacity) {
    char error[PCAP_ERRBUF_SIZE] = "";
    pcap_if_t *devices = NULL;
    size_t used = 0;

    if (capacity == 0 || pcap_findalldevs(&devices, error) == -1) {
        return -1;
    }

    out[0] = '\0';

    for (const pcap_if_t *device = devices; device != NULL; device = device->next) {
        /* Exclude libpcap pseudo-devices, but retain disconnected OS
         * interfaces so viewers can explain why they cannot be selected. */
        if (if_nametoindex(device->name) == 0 || strpbrk(device->name, " \t\r\n/") != NULL) {
            continue;
        }

        pcap_t *handle = pcap_open_live(device->name, 65535, 0, 1000, error);
        const char *support = "unavailable";

        if (handle != NULL) {
            support = pcap_datalink(handle) == DLT_EN10MB && pcap_get_selectable_fd(handle) != -1
                ? "supported" : "unsupported";
            pcap_close(handle);
        }

        const int written = snprintf(out + used, capacity - used, "%s\t%s\t%s\n", device->name,
                                     active_ip_interface(device) ? "active" : "inactive", support);

        if (written < 0 || (size_t)written >= capacity - used) {
            pcap_freealldevs(devices);

            return -1;
        }

        used += (size_t)written;
    }

    pcap_freealldevs(devices);

    return 0;
}
