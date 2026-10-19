#ifndef PIGEON_CAPTURE_H
#define PIGEON_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

/* Selects an openable Ethernet capture source with a selectable descriptor.
 * Automatic selection prefers the routed interface, then an up/running,
 * non-loopback interface with an IP address (in libpcap enumeration order).
 * Explicit selection probes only preferred. Requires capture privileges.
 * Writes the selected name on success; leaves out untouched on failure.
 * Selection is a startup snapshot, not monitoring or automatic failover. */
int capture_select_interface(const char *preferred, int explicit_selection,
                             char *out, size_t capacity);

/* Writes tab-delimited interface inventory; see control/control.h. */
int capture_interface_list(char *out, size_t capacity);

struct capture_source;
struct capture_source *capture_source_open(const char *name);
void capture_source_close(struct capture_source *source);

/*
 * Per-packet callback.
 *
 * data     First byte of the captured frame (its Ethernet header).
 *          Valid only until the callback returns; copy what you keep.
 * caplen   Number of bytes actually captured and readable at data.
 * wirelen  Original length of the frame on the wire (>= caplen).
 * timestamp Capture time in Unix seconds; subsecond precision is discarded.
 * user     Pointer passed to capture_run_live().
 */
typedef void (*capture_cb)(const uint8_t *data, uint32_t caplen,
                           uint32_t wirelen, int64_t timestamp, void *user);

/*
 * Captures packets on the interface `ifname` and invokes `cb` for each
 * one, blocking until capture ends.
 *
 * While running, SIGINT and SIGTERM stop the capture. Their previous
 * handlers are restored before the function returns.
 *
 * Returns 0 when capture ends normally, including a stop by signal, and
 * -1 on error, including when the source's link type is not Ethernet.
 * Errors are reported on stderr.
 */
int capture_run_live(const char *ifname, capture_cb cb, void *user);

/*
 * Reads the pcap savefile at `path` and invokes `cb` for each packet in
 * file order, returning after the last one. Signal handling and return
 * values are the same as for capture_run_live().
 */
int capture_run_file(const char *path, capture_cb cb, void *user);

/* Called during live capture, including idle periods, with current Unix
 * seconds. Runs on the capture thread and may call capture_stop(). */
typedef void (*capture_tick_cb)(int64_t now, void *user);

/* Same ownership and return semantics as capture_run_live(), with periodic
 * ticks at roughly one-second intervals while idle. Requires a selectable
 * capture descriptor. NULL tick preserves capture_run_live() behavior. */
int capture_run_live_tick(const char *ifname, capture_cb cb, capture_tick_cb tick, void *user);

/* Consumes source, including on error. Prepared before a source switch so
 * opening failures do not interrupt the current capture. */
int capture_source_run(struct capture_source *source, capture_cb cb, capture_tick_cb tick, void *user);

/* Requests termination of the current capture loop. Intended for callbacks;
 * has no effect when no capture is running. */
void capture_stop(void);

/* Distinguishes user termination from a requested interface switch. */
int capture_was_signalled(void);

#endif
