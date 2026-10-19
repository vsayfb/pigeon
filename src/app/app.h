#ifndef PIGEON_APP_H
#define PIGEON_APP_H

#include "flow/flow_key.h"

struct app_resolver;

/* Live-only background socket/owner sampler. Captures the caller's network
 * namespace. The returned resolver owns its worker and must be destroyed.
 * Returns NULL with errno set if unavailable. No process details are persisted. */
struct app_resolver *app_resolver_create(void);
void app_resolver_destroy(struct app_resolver *resolver);

/* Flow callback. Copies an executable basename into out, or an empty string
 * for a missing, stale, inaccessible or ambiguous association. The full local
 * port is used only for socket matching, not persisted in the conversation key.
 * This reads cached data only and performs no filesystem or Netlink operations. */
void app_resolver_lookup(const struct flow_key *key, uint16_t local_port,
                          char out[FLOW_APP_LEN], void *resolver);

#endif
