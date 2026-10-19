#ifndef PIGEON_FLOW_H
#define PIGEON_FLOW_H

#include "flow/flow_table.h"
#include "proto/packet.h"

struct flow;

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
 * packets are ignored. At capacity, a new key hands the oldest entry to the
 * eviction handler before freeing it. Without a handler it fails with ENOSPC.
 * A failed handler preserves the entry and rejects the new observation.
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
 * flow_evict_cb semantics and must not modify the tracker. NULL disables
 * handoff and makes new keys at capacity fail with ENOSPC. Destruction does
 * not invoke this callback; pending entries must be consumed before teardown. */
void flow_set_eviction_handler(struct flow *flow, flow_evict_cb cb, void *user);

#endif
