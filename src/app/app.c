#include "app/app_internal.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct app_resolver {
    pthread_t worker;
    pthread_mutex_t mutex;
    pthread_cond_t wake;
    struct app_snapshot *snapshot;
    int stopping;
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

void app_snapshot_lookup(const struct app_snapshot *snapshot, const struct flow_key *key,
                           uint16_t local_port, char out[FLOW_APP_LEN]) {
    out[0] = '\0';

    if (snapshot == NULL) {
        return;
    }

    size_t low = 0;
    size_t high = snapshot->count;

    while (low < high) {
        const size_t middle = low + (high - low) / 2;

        if (snapshot->sockets[middle].local_port < local_port) {
            low = middle + 1;
        } else {
            high = middle;
        }
    }

    int best = -1;
    int ambiguous = 0;

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

        const int score = (!local_any ? 1 : 0) + (!remote_any ? 2 : 0);

        if (score < best) {
            continue;
        }

        if (score > best) {
            best = score;
            ambiguous = socket->ambiguous || !socket->owner_seen;
            memcpy(out, socket->application, FLOW_APP_LEN);
        } else if (socket->ambiguous || !socket->owner_seen ||
                   strcmp(out, socket->application) != 0) {
            ambiguous = 1;
        }
    }

    if (ambiguous) {
        out[0] = '\0';
    }
}

#ifdef __linux__
static void *sample_worker(void *context) {
    struct app_resolver *resolver = context;

    for (;;) {
        const double started = monotonic_now();
        struct app_snapshot *next = app_snapshot_read();

        if (next != NULL) {
            next->sampled_at = started;
            app_snapshot_sort(next);
        }

        pthread_mutex_lock(&resolver->mutex);

        struct app_snapshot *previous = resolver->snapshot;

        resolver->snapshot = next;
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

    if (snapshot != NULL && snapshot->sampled_at >= 0 && now >= snapshot->sampled_at &&
        now - snapshot->sampled_at <= 3.0) {
        app_snapshot_lookup(snapshot, key, local_port, out);
    }

    pthread_mutex_unlock(&resolver->mutex);
}
