#include "dns/dns_cache.h"
#include "store/store.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define DNS_CACHE_BUCKETS 256

struct cache_entry {
    struct store_dns_row row;
    struct cache_entry *next;
};

struct dns_cache {
    struct store *store;
    size_t capacity;
    size_t count;

    struct cache_entry *buckets[DNS_CACHE_BUCKETS];
};

static size_t bucket_for(struct ip_addr ip) {
    return ip_addr_hash(&ip) % DNS_CACHE_BUCKETS;
}

static struct cache_entry *find_entry(const struct dns_cache *cache, struct ip_addr ip) {
    for (struct cache_entry *entry = cache->buckets[bucket_for(ip)];
         entry != NULL; entry = entry->next) {
        if (ip_addr_equal(&entry->row.ip, &ip)) {
            return entry;
        }
    }

    return NULL;
}

static void make_room(struct dns_cache *cache, int64_t now) {
    struct cache_entry **victim = NULL;

    for (size_t i = 0; i < DNS_CACHE_BUCKETS; i++) {
        for (struct cache_entry **link = &cache->buckets[i];
             *link != NULL; link = &(*link)->next) {
            if ((*link)->row.expires_at <= now) {
                victim = link;
                break;
            }

            if (victim == NULL || (*link)->row.observed_at < (*victim)->row.observed_at) {
                victim = link;
            }
        }

        if (victim != NULL && (*victim)->row.expires_at <= now) {
            break;
        }
    }

    if (victim != NULL) {
        struct cache_entry *entry = *victim;

        *victim = entry->next;
        free(entry);
        cache->count--;
    }
}

static void insert_entry(struct dns_cache *cache, struct cache_entry *entry, int64_t now) {
    if (cache->count == cache->capacity) {
        make_room(cache, now);
    }

    const size_t bucket = bucket_for(entry->row.ip);

    entry->next = cache->buckets[bucket];
    cache->buckets[bucket] = entry;
    cache->count++;
}

static int load_row(const struct store_dns_row *row, void *user) {
    struct dns_cache *cache = user;
    struct cache_entry *entry = malloc(sizeof *entry);

    if (entry == NULL) {
        return -1;
    }

    entry->row = *row;
    insert_entry(cache, entry, INT64_MIN);

    return 0;
}

struct dns_cache *dns_cache_create(struct store *store, size_t capacity, int64_t now) {
    if (store == NULL || capacity == 0) {
        errno = EINVAL;

        return NULL;
    }

    struct dns_cache *cache = calloc(1, sizeof *cache);

    if (cache == NULL) {
        return NULL;
    }

    cache->store = store;
    cache->capacity = capacity;
    errno = 0;

    if (store_dns_load(store, now, load_row, cache) == -1) {
        const int saved_errno = errno == ENOMEM ? ENOMEM : EIO;

        dns_cache_destroy(cache);
        errno = saved_errno;

        return NULL;
    }

    return cache;
}

void dns_cache_clear(struct dns_cache *cache) {
    if (cache == NULL) {
        return;
    }

    for (size_t i = 0; i < DNS_CACHE_BUCKETS; i++) {
        struct cache_entry *entry = cache->buckets[i];

        while (entry != NULL) {
            struct cache_entry *next = entry->next;

            free(entry);
            entry = next;
        }

        cache->buckets[i] = NULL;
    }

    cache->count = 0;
}

void dns_cache_destroy(struct dns_cache *cache) {
    dns_cache_clear(cache);
    free(cache);
}

int dns_cache_update(struct dns_cache *cache, const struct dns_answer *answer, int64_t now) {
    if (answer->name[0] == '\0' || memchr(answer->name, '\0', sizeof answer->name) == NULL) {
        errno = EINVAL;

        return -1;
    }

    struct cache_entry *entry = find_entry(cache, answer->ip);

    if (entry != NULL && now < entry->row.observed_at) {
        return 0;
    }

    struct cache_entry *allocated = entry == NULL ? malloc(sizeof *allocated) : NULL;

    if (entry == NULL && allocated == NULL) {
        return -1;
    }

    struct store_dns_row row = {
        .ip = answer->ip,
        .observed_at = now,
        .expires_at = now > INT64_MAX - (int64_t)answer->ttl
                      ? INT64_MAX : now + (int64_t)answer->ttl
    };

    memcpy(row.name, answer->name, strlen(answer->name) + 1);

    const int saved = store_dns_save(cache->store, &row);

    if (saved <= 0) {
        free(allocated);

        if (saved == -1) {
            errno = EIO;
        }

        return saved;
    }

    if (entry == NULL) {
        allocated->row = row;
        insert_entry(cache, allocated, now);
    } else {
        entry->row = row;
    }

    return 1;
}

const char *dns_cache_lookup(const struct dns_cache *cache, struct ip_addr ip, int64_t now) {
    const struct cache_entry *entry = find_entry(cache, ip);

    if (entry == NULL || now < entry->row.observed_at || now >= entry->row.expires_at) {
        return NULL;
    }

    return entry->row.name;
}

void dns_cache_expire(struct dns_cache *cache, int64_t now) {
    for (size_t i = 0; i < DNS_CACHE_BUCKETS; i++) {
        struct cache_entry **link = &cache->buckets[i];

        while (*link != NULL) {
            struct cache_entry *entry = *link;

            if (entry->row.expires_at <= now) {
                *link = entry->next;
                free(entry);
                cache->count--;
            } else {
                link = &entry->next;
            }
        }
    }
}

int dns_cache_observe_addresses(struct dns_cache *cache, const struct packet_view *packet,
                                 const struct ip_addr *locals, size_t local_count, int64_t now) {
    if (packet->kind != PACKET_UDP || packet->transport.udp.src_port != 53) {
        return 0;
    }

    const struct ip_addr destination = packet_destination(packet);
    int local = 0;

    for (size_t i = 0; i < local_count; i++) {
        local |= ip_addr_equal(&destination, &locals[i]);
    }

    if (!local) {
        return 0;
    }

    struct dns_answer answers[DNS_MAX_ANSWERS];
    size_t count;

    if (dns_parse_response(packet->transport.udp.payload, packet->transport.udp.payload_len,
                           answers, DNS_MAX_ANSWERS, &count) == DNS_PARSE_INVALID) {
        return 0;
    }

    int saved = 0;

    for (size_t i = 0; i < count; i++) {
        const int rc = dns_cache_update(cache, &answers[i], now);

        if (rc == -1) {
            return -1;
        }

        saved += rc;
    }

    return saved;
}

int dns_cache_observe(struct dns_cache *cache, const struct packet_view *packet,
                       uint32_t local_ip, int64_t now) {
    const struct ip_addr local = ip_addr_v4(local_ip);

    return dns_cache_observe_addresses(cache, packet, &local, 1, now);
}
