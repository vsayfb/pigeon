#ifndef PIGEON_DNS_CACHE_H
#define PIGEON_DNS_CACHE_H

#include "dns/dns_parse.h"
#include "proto/packet.h"

struct store;
struct dns_cache;

/* Creates a bounded IP-to-name map and loads saved rows unexpired at now.
 * Store is borrowed and must outlive the cache. capacity must be positive.
 * Use INT64_MIN when replay time is not yet known; lookups still check time.
 * Returns the owned cache, or NULL with errno set on allocation/load failure.
 * Release with dns_cache_destroy(). Database errors are in store_error(). */
struct dns_cache *dns_cache_create(struct store *store, size_t capacity, int64_t now);

/* Frees the map without deleting persisted mappings. Accepts NULL. */
void dns_cache_destroy(struct dns_cache *cache);

/* Writes one mapping through to SQLite, then updates memory. now is Unix
 * seconds; TTL zero invalidates the previous mapping. Expiry saturates at
 * INT64_MAX. Older observations cannot replace newer ones. At capacity the
 * oldest observed mapping is removed from memory, preferring expired rows.
 * Returns 1 if saved, 0 if older and ignored, or -1 with errno set on failure,
 * leaving memory unchanged. Database failures set EIO and store_error(). */
int dns_cache_update(struct dns_cache *cache, const struct dns_answer *answer, int64_t now);

/* Returns a borrowed name only for observed_at <= now < expires_at, or NULL.
 * The pointer is valid until the next update, expiry or destruction. */
const char *dns_cache_lookup(const struct dns_cache *cache, uint32_t ip, int64_t now);

/* Removes expired mappings from memory, retaining their SQLite rows. */
void dns_cache_expire(struct dns_cache *cache, int64_t now);

/* Observes incoming UDP/53 responses addressed to local_ip. Malformed DNS
 * messages are ignored; complete records from partial replies are accepted.
 * Returns the number saved, 0 if ignored, or -1 with errno set on failure.
 * Each mapping is saved atomically; earlier mappings remain saved if a later
 * save fails. No packet bytes are retained. */
int dns_cache_observe(struct dns_cache *cache, const struct packet_view *packet,
                       uint32_t local_ip, int64_t now);

#endif
