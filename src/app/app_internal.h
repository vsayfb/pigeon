#ifndef PIGEON_APP_INTERNAL_H
#define PIGEON_APP_INTERNAL_H

#include "app/app.h"

struct app_socket {
    struct ip_addr local;
    struct ip_addr remote;
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t protocol;
    uint32_t inode;
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
void app_snapshot_lookup(const struct app_snapshot *snapshot, const struct flow_key *key,
                           uint16_t local_port, char out[FLOW_APP_LEN]);

#endif
