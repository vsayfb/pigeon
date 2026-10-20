#include "app/app_internal.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEBUG_SLOTS 128
#define DEBUG_LINES_PER_SECOND 20

struct app_debug_slot {
    struct flow_key key;
    uint16_t local_port;
    enum app_lookup_reason reason;
    int sample_error;
    double logged_at;
    int valid;
};

struct app_resolver {
    pthread_t worker;
    pthread_mutex_t mutex;
    pthread_cond_t wake;
    struct app_snapshot *snapshot;
    int stopping;
    int debug;
    int sample_error;
    struct app_debug_slot debug_slots[DEBUG_SLOTS];
    int64_t debug_second;
    unsigned debug_lines;
    unsigned debug_suppressed;
};

static double monotonic_now(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
        return -1;
    }

    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}

void app_snapshot_destroy(struct app_snapshot *snapshot) {
    if (snapshot != NULL) {
        free(snapshot->sockets);
        free(snapshot);
    }
}

static int compare_port(const void *a, const void *b) {
    const struct app_socket *left = a;
    const struct app_socket *right = b;

    return (left->local_port > right->local_port) - (left->local_port < right->local_port);
}

void app_snapshot_sort(struct app_snapshot *snapshot) {
    if (snapshot->count > 1) {
        qsort(snapshot->sockets, snapshot->count, sizeof *snapshot->sockets, compare_port);
    }
}

static int unspecified(const struct ip_addr *address) {
    for (size_t i = 0; i < ip_addr_size(address); i++) {
        if (address->bytes[i] != 0) {
            return 0;
        }
    }

    return 1;
}

#define OWNER_CACHE_SECONDS 5.0

static size_t first_port(const struct app_snapshot *snapshot, uint16_t port) {
    size_t low = 0;
    size_t high = snapshot->count;

    while (low < high) {
        const size_t middle = low + (high - low) / 2;

        if (snapshot->sockets[middle].local_port < port) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    return low;
}

void app_snapshot_cache_owners(struct app_snapshot *next, const struct app_snapshot *previous, double now) {
    for (size_t i = 0; i < next->count; i++) {
        struct app_socket *socket = &next->sockets[i];

        if (socket->owner_seen) {
            socket->owner_confirmed_at = now;
            socket->owner_cached = 0;

            continue;
        }

        if (previous == NULL || socket->ambiguous || !socket->cookie_valid || socket->inode == 0 || now < 0) {
            continue;
        }

        const struct app_socket *match = NULL;

        for (size_t j = first_port(previous, socket->local_port);
             j < previous->count && previous->sockets[j].local_port == socket->local_port; j++) {
            const struct app_socket *old = &previous->sockets[j];

            if (!old->cookie_valid || old->cookie != socket->cookie || old->inode != socket->inode ||
                old->protocol != socket->protocol || old->remote_port != socket->remote_port ||
                !ip_addr_equal(&old->local, &socket->local) || !ip_addr_equal(&old->remote, &socket->remote)) {
                continue;
            }

            if (!old->owner_seen || old->ambiguous || old->application[0] == '\0' ||
                now < old->owner_confirmed_at || now - old->owner_confirmed_at >= OWNER_CACHE_SECONDS) {
                match = NULL;
                break;
            }

            if (match != NULL && strcmp(match->application, old->application) != 0) {
                match = NULL;
                break;
            }

            match = old;
        }

        if (match != NULL) {
            memcpy(socket->application, match->application, sizeof socket->application);
            socket->owner_seen = 1;
            socket->owner_cached = 1;
            socket->owner_confirmed_at = match->owner_confirmed_at;
        }
    }
}

void app_snapshot_lookup(const struct app_snapshot *snapshot, const struct flow_key *key,
                           uint16_t local_port, char out[FLOW_APP_LEN]) {
    app_snapshot_lookup_at(snapshot, key, local_port, snapshot != NULL ? snapshot->sampled_at : 0, out);
}

void app_snapshot_lookup_at(const struct app_snapshot *snapshot, const struct flow_key *key,
                            uint16_t local_port, double now, char out[FLOW_APP_LEN]) {
    (void)app_snapshot_diagnose(snapshot, key, local_port, now, out);
}

enum app_lookup_reason app_snapshot_diagnose(const struct app_snapshot *snapshot, const struct flow_key *key,
                                             uint16_t local_port, double now, char out[FLOW_APP_LEN]) {
    out[0] = '\0';

    if (snapshot == NULL) {
        return APP_LOOKUP_NO_SNAPSHOT;
    }

    const size_t low = first_port(snapshot, local_port);

    int best = -1;
    int missing = 0;
    int ambiguous = 0;
    int expired = 0;
    int cached = 0;

    for (size_t i = low; i < snapshot->count && snapshot->sockets[i].local_port == local_port; i++) {
        const struct app_socket *socket = &snapshot->sockets[i];
        const int local_any = unspecified(&socket->local);
        const int remote_any = socket->remote_port == 0 && unspecified(&socket->remote);

        if (socket->protocol != key->protocol || socket->local.family != key->us_ip.family ||
            (!local_any && !ip_addr_equal(&socket->local, &key->us_ip)) ||
            (remote_any && key->protocol != 17) ||
            (!remote_any && (socket->remote_port != key->remote_port ||
                            !ip_addr_equal(&socket->remote, &key->remote_ip)))) {
            continue;
        }

        const int owner_expired = socket->owner_cached &&
            (now < socket->owner_confirmed_at || now - socket->owner_confirmed_at >= OWNER_CACHE_SECONDS);
        const int score = (!local_any ? 1 : 0) + (!remote_any ? 2 : 0);

        if (score < best) {
            continue;
        }

        if (score > best) {
            best = score;
            missing = !socket->owner_seen || socket->application[0] == '\0';
            ambiguous = socket->ambiguous && socket->application[0] != '\0';
            expired = owner_expired;
            cached = socket->owner_cached;
            memcpy(out, socket->application, FLOW_APP_LEN);
        } else {
            if ((socket->ambiguous && socket->application[0] != '\0') ||
                (out[0] != '\0' && socket->application[0] != '\0' && strcmp(out, socket->application) != 0)) {
                ambiguous = 1;
            }

            missing |= !socket->owner_seen || socket->application[0] == '\0';
            expired |= owner_expired;
            cached &= socket->owner_cached;
        }
    }

    if (best == -1) {
        return APP_LOOKUP_NO_SOCKET;
    }

    if (ambiguous || missing || expired) {
        out[0] = '\0';

        return ambiguous ? APP_LOOKUP_AMBIGUOUS : expired ? APP_LOOKUP_CACHE_EXPIRED : APP_LOOKUP_OWNER_MISSING;
    }

    return cached ? APP_LOOKUP_CACHE : APP_LOOKUP_SNAPSHOT;
}

#ifdef __linux__
static void *sample_worker(void *context) {
    struct app_resolver *resolver = context;

    for (;;) {
        const double started = monotonic_now();
        struct app_snapshot *next = app_snapshot_read();
        const int sample_error = next != NULL ? 0 : (errno != 0 ? errno : EIO);

        if (next != NULL) {
            next->sampled_at = started;
            app_snapshot_sort(next);
        }

        /* Only this worker replaces/frees snapshots; destruction joins it.
         * Build the cache outside the lookup lock so capture never waits on
         * the ownership merge itself. The previous snapshot stays immutable. */
        struct app_snapshot *previous = resolver->snapshot;

        if (next != NULL) {
            app_snapshot_cache_owners(next, previous, started);
        }

        pthread_mutex_lock(&resolver->mutex);

        resolver->sample_error = sample_error;

        if (next != NULL) {
            resolver->snapshot = next;
        } else {
            previous = NULL;
        }

        /* A failed sample leaves the previous snapshot available only until
         * its original three-second freshness deadline; never renew it. */
        pthread_mutex_unlock(&resolver->mutex);
        app_snapshot_destroy(previous);

        struct timespec deadline;

        if (clock_gettime(CLOCK_MONOTONIC, &deadline) == -1) {
            return NULL;
        }

        deadline.tv_sec++;
        pthread_mutex_lock(&resolver->mutex);

        while (!resolver->stopping) {
            if (pthread_cond_timedwait(&resolver->wake, &resolver->mutex, &deadline) != 0) {
                break;
            }
        }

        const int stopping = resolver->stopping;

        pthread_mutex_unlock(&resolver->mutex);

        if (stopping) {
            return NULL;
        }
    }
}
#endif

struct app_resolver *app_resolver_create(void) {
#ifndef __linux__
    errno = ENOSYS;

    return NULL;
#else
    struct app_resolver *resolver = calloc(1, sizeof *resolver);

    if (resolver == NULL) {
        return NULL;
    }

    int rc = pthread_mutex_init(&resolver->mutex, NULL);

    if (rc != 0) {
        free(resolver);
        errno = rc;

        return NULL;
    }

    pthread_condattr_t attributes;

    rc = pthread_condattr_init(&attributes);

    if (rc == 0) {
        rc = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);

        if (rc == 0) {
            rc = pthread_cond_init(&resolver->wake, &attributes);
        }

        pthread_condattr_destroy(&attributes);
    }

    if (rc != 0) {
        pthread_mutex_destroy(&resolver->mutex);
        free(resolver);
        errno = rc;

        return NULL;
    }

    /* The capture thread owns SIGINT/SIGTERM handling. Inherit a blocked mask
     * so its handlers never run concurrently on this sampler thread. */
    sigset_t blocked;
    sigset_t previous;

    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    rc = pthread_sigmask(SIG_BLOCK, &blocked, &previous);

    if (rc == 0) {
        rc = pthread_create(&resolver->worker, NULL, sample_worker, resolver);
        pthread_sigmask(SIG_SETMASK, &previous, NULL);
    }

    if (rc != 0) {
        pthread_cond_destroy(&resolver->wake);
        pthread_mutex_destroy(&resolver->mutex);
        free(resolver);
        errno = rc;

        return NULL;
    }

    return resolver;
#endif
}

void app_resolver_destroy(struct app_resolver *resolver) {
    if (resolver == NULL) {
        return;
    }

    pthread_mutex_lock(&resolver->mutex);
    resolver->stopping = 1;
    pthread_cond_signal(&resolver->wake);
    pthread_mutex_unlock(&resolver->mutex);
    pthread_join(resolver->worker, NULL);

    app_snapshot_destroy(resolver->snapshot);
    pthread_cond_destroy(&resolver->wake);
    pthread_mutex_destroy(&resolver->mutex);
    free(resolver);
}

void app_resolver_set_debug(struct app_resolver *resolver, int enabled) {
    pthread_mutex_lock(&resolver->mutex);
    resolver->debug = enabled;
    pthread_mutex_unlock(&resolver->mutex);
}

static void debug_lookup(struct app_resolver *resolver, const struct flow_key *key, uint16_t port,
                          double now, double age, enum app_lookup_reason reason, const char *application) {
    static const char *reasons[] = { "snapshot", "cache", "no-snapshot", "stale-snapshot", "no-matching-socket",
                                    "owner-missing", "ambiguous-owners", "owner-cache-expired", "clock-error" };
    const size_t bucket = (flow_key_hash(key) ^ port) % DEBUG_SLOTS;
    struct app_debug_slot *slot = &resolver->debug_slots[bucket];
    struct flow_key observed = *key;

    memcpy(observed.application, application, strlen(application) + 1);

    if (slot->valid && slot->local_port == port && slot->reason == reason &&
        slot->sample_error == resolver->sample_error &&
        flow_key_equal(&slot->key, &observed) && now >= slot->logged_at && now - slot->logged_at < 5.0) {
        return;
    }

    const int64_t second = now >= 0 ? (int64_t)now : 0;

    if (second != resolver->debug_second) {
        if (resolver->debug_suppressed != 0) {
            fprintf(stderr, "attribution rate-limited=%u\n", resolver->debug_suppressed);
        }

        resolver->debug_second = second;
        resolver->debug_lines = 0;
        resolver->debug_suppressed = 0;
    }

    if (resolver->debug_lines >= DEBUG_LINES_PER_SECOND) {
        resolver->debug_suppressed++;

        return;
    }

    *slot = (struct app_debug_slot){ .key = observed, .local_port = port, .reason = reason,
                                     .sample_error = resolver->sample_error, .logged_at = now, .valid = 1 };
    resolver->debug_lines++;

    char local[IP_ADDR_STR_LEN];
    char remote[IP_ADDR_STR_LEN];
    char safe_application[FLOW_APP_LEN];

    for (size_t i = 0; i < sizeof safe_application; i++) {
        const unsigned char byte = (unsigned char)application[i];

        safe_application[i] = byte >= 32 && byte <= 126 ? (char)byte : '?';

        if (byte == 0) {
            safe_application[i] = '\0';
            break;
        }
    }

    safe_application[sizeof safe_application - 1] = '\0';

    fprintf(stderr, "attribution local=[%s]:%u peer=[%s]:%u proto=%u owner=%s result=%s snapshot_age=%.3fs sample_errno=%d\n",
            ip_addr_str(&key->us_ip, local), port, ip_addr_str(&key->remote_ip, remote), key->remote_port,
            key->protocol, safe_application[0] ? safe_application : "-", reasons[reason], age, resolver->sample_error);
}

void app_resolver_lookup(const struct flow_key *key, uint16_t local_port,
                          char out[FLOW_APP_LEN], void *context) {
    struct app_resolver *resolver = context;

    out[0] = '\0';

    if (resolver == NULL) {
        return;
    }

    const double now = monotonic_now();

    pthread_mutex_lock(&resolver->mutex);

    const struct app_snapshot *snapshot = resolver->snapshot;

    enum app_lookup_reason reason = APP_LOOKUP_NO_SNAPSHOT;
    const double age = snapshot != NULL ? now - snapshot->sampled_at : -1;

    if (now < 0) {
        reason = APP_LOOKUP_CLOCK_ERROR;
    } else if (snapshot != NULL) {
        reason = APP_LOOKUP_STALE;

        if (snapshot->sampled_at >= 0 && now >= snapshot->sampled_at && age <= 3.0) {
            reason = app_snapshot_diagnose(snapshot, key, local_port, now, out);
        }
    }

    if (resolver->debug) {
        debug_lookup(resolver, key, local_port, now, age, reason, out);
    }

    pthread_mutex_unlock(&resolver->mutex);
}
