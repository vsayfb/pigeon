#ifndef PIGEON_FLOW_H
#define PIGEON_FLOW_H

#include "flow/flow_table.h"
#include "proto/packet.h"

struct flow;
struct store;

/*
 * Creates a tracker for local_ip (host byte order), owning a conversation
 * table with the specified bucket count and capacity. The caller releases
 * the tracker with flow_destroy().
 *
 * Returns the tracker on success. Returns NULL with errno set on allocation
 * failure or invalid table dimensions, as in flow_table_create().
 */
struct flow *flow_create(uint32_t local_ip, size_t bucket_count, size_t capacity);

/* Frees the tracker and all its entries without flushing. Accepts NULL. */
void flow_destroy(struct flow *flow);

/*
 * Observes a successfully parsed packet, updating its conversation's pending
 * packet and payload-byte deltas and moving the entry to newest. now is an
 * absolute Unix timestamp in seconds; first_seen and last_seen track the
 * minimum and maximum observed times. Bytes use payload_wire_len, including
 * payload omitted by capture truncation. Zero-payload packets still count.
 * Outgoing and incoming traffic use the remote endpoint's port; local ports
 * are excluded. The packet and its payload are borrowed only for this call.
 * Only TCP/UDP packets with exactly one endpoint equal to local_ip qualify.
 * Unsupported protocols, later fragments, unrelated and local-to-local
 * packets are ignored. At capacity, a new key flushes the oldest entry to
 * attached storage, or hands it to the eviction handler, before freeing it.
 * Without either sink it fails with ENOSPC. A failed write or handler
 * preserves the entry and rejects the new observation.
 *
 * Returns 1 for an observed conversation, 0 for an ignored packet, or -1
 * with errno set on allocation or handoff failure, leaving the tracker unchanged.
 */
int flow_observe(const struct flow *flow, const struct packet_view *packet, int64_t now);

/* Returns the number of conversations currently held by the tracker. */
size_t flow_count(const struct flow *flow);

/* Returns a borrowed entry, or NULL if absent. Does not change recency.
 * The entry remains valid until eviction or tracker destruction. */
const struct flow_entry *flow_find(const struct flow *flow, const struct flow_key *key);

/* Sets the callback used to hand off pending deltas on capacity eviction.
 * Context is borrowed until replaced or destruction. The callback follows
 * flow_evict_cb semantics and must not modify the tracker. Without attached
 * storage, NULL makes new keys at capacity fail with ENOSPC. Destruction does
 * not invoke this callback; pending entries must be consumed before teardown. */
void flow_set_eviction_handler(struct flow *flow, flow_evict_cb cb, void *user);

/* Visits each current entry from newest to oldest. Entries and user are
 * borrowed for the call. The visitor must not modify or destroy the tracker. */
void flow_visit(const struct flow *flow,
                void (*visit)(const struct flow_entry *entry, void *user), void *user);

/* Attaches borrowed storage, which must outlive the tracker or be detached.
 * Storage takes precedence over the custom eviction handler. */
void flow_set_store(struct flow *flow, struct store *store);

/*
 * Snapshots all dirty entries and writes one transaction. On success clears
 * only their packet/byte deltas, retaining first_seen and last_seen. No-op
 * for clean entries. This operation bypasses the periodic throttle.
 *
 * Returns 0 on success. Returns -1 with errno set on failure, preserving
 * pending deltas. Missing storage sets ENOSYS; database failures set EIO
 * and leave details in store_error(). Allocation failures set ENOMEM.
 */
int flow_flush(struct flow *flow);

/*
 * Attempts a batch flush at most once per second using Unix seconds now,
 * then expires UDP entries idle for at least 30s and TCP entries idle for
 * at least 120s. The first call runs immediately. Same-second and backward
 * ticks are skipped; failed attempts are also throttled. Expiry follows a
 * successful flush, so failed writes preserve entries and deltas.
 *
 * Returns 0 on success or a skipped tick. Returns -1 with the same error
 * semantics as flow_flush(). Call flow_flush() before shutdown/destroy.
 */
int flow_tick(struct flow *flow, int64_t now);

#endif
