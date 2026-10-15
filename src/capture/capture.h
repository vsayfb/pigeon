#ifndef PIGEON_CAPTURE_H
#define PIGEON_CAPTURE_H

#include <stdint.h>

/*
 * Per-packet callback.
 *
 * data     First byte of the captured frame (link-layer header).
 *          Valid only until the callback returns; copy what you keep.
 * caplen   Number of bytes actually captured and readable at data.
 * wirelen  Original length of the frame on the wire (>= caplen).
 * user     Pointer passed to capture_run_live().
 */
typedef void (*capture_cb)(const uint8_t *data, uint32_t caplen,
                           uint32_t wirelen, void *user);

/*
 * Captures packets on the interface `ifname` and invokes `cb` for each
 * one, blocking until capture ends.
 *
 * While running, SIGINT and SIGTERM stop the capture. Their previous
 * handlers are restored before the function returns.
 *
 * Returns 0 when capture ends normally, including a stop by signal, and
 * -1 on error. Errors are reported on stderr.
 */
int capture_run_live(const char *ifname, capture_cb cb, void *user);

#endif
