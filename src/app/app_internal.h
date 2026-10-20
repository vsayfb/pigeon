#ifndef PIGEON_APP_INTERNAL_H
#define PIGEON_APP_INTERNAL_H

#include "app/app.h"

enum app_lookup_reason {
    APP_LOOKUP_SNAPSHOT,
    APP_LOOKUP_CACHE,
    APP_LOOKUP_NO_SNAPSHOT,
    APP_LOOKUP_STALE,
    APP_LOOKUP_NO_SOCKET,
    APP_LOOKUP_OWNER_MISSING,
    APP_LOOKUP_AMBIGUOUS,
    APP_LOOKUP_CACHE_EXPIRED,
    APP_LOOKUP_CLOCK_ERROR
};

struct app_socket {
    struct ip_addr local;
    struct ip_addr remote;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t protocol;
    uint32_t inode;
    uint64_t cookie;
    int cookie_valid;
    double owner_confirmed_at;
    int owner_cached;
    char application[FLOW_APP_LEN];
    int owner_seen;
    int ambiguous;
};

struct app_snapshot {
    struct app_socket *sockets;
    size_t count;
    double sampled_at;
};

/* Backend returns a complete snapshot or NULL with errno set. */
struct app_snapshot *app_snapshot_read(void);
void app_snapshot_destroy(struct app_snapshot *snapshot);

/* Sort once after reading; match uses a local-port index and rejects ties
 * with missing/different owners. Exposed here for deterministic backend tests. */
void app_snapshot_sort(struct app_snapshot *snapshot);

/* Both snapshots are sorted by local port. Carry confirmed ownership for at
 * most five seconds, only for the same kernel cookie/inode and socket tuple.
 * Missing sockets and ambiguous/conflicting ownership never inherit it. */
void app_snapshot_cache_owners(struct app_snapshot *next, const struct app_snapshot *previous, double now);
enum app_lookup_reason app_snapshot_diagnose(const struct app_snapshot *snapshot, const struct flow_key *key,
                                             uint16_t local_port, double now, char out[FLOW_APP_LEN]);
void app_snapshot_lookup_at(const struct app_snapshot *snapshot, const struct flow_key *key,
                            uint16_t local_port, double now, char out[FLOW_APP_LEN]);
void app_snapshot_lookup(const struct app_snapshot *snapshot, const struct flow_key *key,
                           uint16_t local_port, char out[FLOW_APP_LEN]);

#endif
