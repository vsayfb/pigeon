#include <errno.h>
#include <string.h>

#include "../t.h"
#include "flow/flow_table.h"

static struct flow_key make_key(uint32_t remote_ip) {
    const struct flow_key key = {
        .us_ip = ip_addr_v4(0xC000020A),
        .remote_ip = ip_addr_v4(remote_ip),
        .remote_port = 443,
        .protocol = 6
    };

    return key;
}

static void test_empty_and_invalid_sizes(void) {
    CHECK(flow_table_create(0, 10000) == NULL);
    CHECK(errno == EINVAL);
    CHECK(flow_table_create(16, 0) == NULL);
    CHECK(errno == EINVAL);
    CHECK(flow_table_create(SIZE_MAX, 10000) == NULL);
    CHECK(errno == ENOMEM);

    struct flow_table *table = flow_table_create(16, 10000);
    const struct flow_key key = make_key(0xC6336414);

    CHECK(table != NULL);
    CHECK(flow_table_count(table) == 0);
    CHECK(flow_table_find(table, &key) == NULL);
    CHECK(flow_table_remove(table, &key) == 0);
    CHECK(flow_table_count(table) == 0);

    flow_table_destroy(table);
    flow_table_destroy(NULL);
}

static void test_duplicate_and_key_ownership(void) {
    struct flow_table *table = flow_table_create(16, 10000);
    struct flow_key key = make_key(0xC6336414);
    const struct flow_key original = key;

    CHECK(table != NULL);

    struct flow_entry *entry = flow_table_insert(table, &key);

    CHECK(entry != NULL);
    CHECK(flow_table_insert(table, &key) == entry);
    CHECK(flow_table_find(table, &key) == entry);
    CHECK(flow_table_count(table) == 1);

    key.remote_port = 80;

    CHECK(flow_key_equal(flow_entry_key(entry), &original));
    CHECK(flow_table_find(table, &original) == entry);
    CHECK(flow_table_find(table, &key) == NULL);

    flow_table_destroy(table);
}

static void test_each_field_is_part_of_identity(void) {
    struct flow_table *table = flow_table_create(16, 10000);
    const struct flow_key original = make_key(0xC6336414);
    struct flow_key keys[5];
    struct flow_entry *entries[5];

    CHECK(table != NULL);

    for (size_t i = 0; i < 5; i++) {
        keys[i] = original;
    }

    keys[1].us_ip.bytes[3]++;
    keys[2].remote_ip.bytes[3]++;
    keys[3].remote_port++;
    keys[4].protocol = 17;

    for (size_t i = 0; i < 5; i++) {
        entries[i] = flow_table_insert(table, &keys[i]);

        CHECK(entries[i] != NULL);
        CHECK(flow_table_count(table) == i + 1);
    }

    for (size_t i = 0; i < 5; i++) {
        CHECK(flow_table_find(table, &keys[i]) == entries[i]);
        CHECK(flow_key_equal(flow_entry_key(entries[i]), &keys[i]));
    }

    flow_table_destroy(table);
}

static void test_padding_does_not_change_identity(void) {
    struct flow_key a;
    struct flow_key b;

    memset(&a, 0xAA, sizeof a);
    memset(&b, 0xBB, sizeof b);

    a.us_ip = b.us_ip = ip_addr_v4(0xC000020A);
    a.remote_ip = b.remote_ip = ip_addr_v4(0xC6336414);
    a.remote_port = b.remote_port = 443;
    a.protocol = b.protocol = 6;
    a.application[0] = b.application[0] = '\0';

    CHECK(flow_key_equal(&a, &b));
    CHECK(flow_key_hash(&a) == flow_key_hash(&b));

    struct flow_table *table = flow_table_create(16, 10000);

    CHECK(table != NULL);

    struct flow_entry *entry = flow_table_insert(table, &a);

    CHECK(entry != NULL);
    CHECK(flow_table_insert(table, &b) == entry);
    CHECK(flow_table_count(table) == 1);

    flow_table_destroy(table);
}

static void test_collision_chain_removal(void) {
    /* One bucket forces every key into the same chain. */
    struct flow_table *table = flow_table_create(1, 10000);
    struct flow_key keys[4];
    struct flow_entry *entries[4];

    CHECK(table != NULL);

    for (size_t i = 0; i < 4; i++) {
        keys[i] = make_key(0xC6336401 + (uint32_t)i);
        entries[i] = flow_table_insert(table, &keys[i]);

        CHECK(entries[i] != NULL);
    }

    /* Insertion prepends: chain order is 3, 2, 1, 0. */
    const size_t removal_order[] = { 2, 3, 0, 1 };
    int removed[4] = { 0 };

    for (size_t i = 0; i < 4; i++) {
        const size_t victim = removal_order[i];

        CHECK(flow_table_remove(table, &keys[victim]) == 1);
        CHECK(flow_table_remove(table, &keys[victim]) == 0);
        CHECK(flow_table_count(table) == 3 - i);

        removed[victim] = 1;

        for (size_t j = 0; j < 4; j++) {
            if (removed[j]) {
                CHECK(flow_table_find(table, &keys[j]) == NULL);
            } else {
                CHECK(flow_table_find(table, &keys[j]) == entries[j]);
            }
        }
    }

    CHECK(flow_table_insert(table, &keys[2]) != NULL);
    CHECK(flow_table_find(table, &keys[2]) != NULL);
    CHECK(flow_table_count(table) == 1);

    flow_table_destroy(table);
}

static void test_ten_thousand_keys(void) {
    struct flow_table *table = flow_table_create(256, 10000);
    struct flow_entry *entries[10000];

    CHECK(table != NULL);

    for (uint32_t i = 0; i < 10000; i++) {
        const struct flow_key key = make_key(0xC6120000 + i);

        entries[i] = flow_table_insert(table, &key);

        CHECK(entries[i] != NULL);
    }

    CHECK(flow_table_count(table) == 10000);

    for (uint32_t i = 0; i < 10000; i++) {
        const struct flow_key key = make_key(0xC6120000 + i);

        CHECK(flow_table_find(table, &key) == entries[i]);
        CHECK(flow_table_insert(table, &key) == entries[i]);
        CHECK(flow_key_equal(flow_entry_key(entries[i]), &key));
    }

    CHECK(flow_table_count(table) == 10000);

    flow_table_destroy(table);
}


static void check_order(const struct flow_table *table,
                        const struct flow_key *keys, size_t count) {
    const struct flow_entry *entry = flow_table_newest(table);

    CHECK(flow_table_count(table) == count);

    for (size_t i = 0; i < count; i++) {
        CHECK(entry != NULL);
        CHECK(flow_key_equal(flow_entry_key(entry), &keys[i]));

        entry = flow_entry_older(entry);
    }

    CHECK(entry == NULL);

    entry = flow_table_oldest(table);

    for (size_t i = count; i > 0; i--) {
        CHECK(entry != NULL);
        CHECK(flow_key_equal(flow_entry_key(entry), &keys[i - 1]));

        entry = flow_entry_newer(entry);
    }

    CHECK(entry == NULL);
}

static void test_capacity_and_order(void) {
    /* One bucket exercises both list links and collision links. */
    struct flow_table *table = flow_table_create(1, 4);
    struct flow_key keys[5];

    CHECK(table != NULL);
    CHECK(flow_table_capacity(table) == 4);

    check_order(table, keys, 0);

    for (size_t i = 0; i < 5; i++) {
        keys[i] = make_key(0xC6336401 + (uint32_t)i);
    }

    for (size_t i = 4; i > 0; i--) {
        CHECK(flow_table_insert(table, &keys[i - 1]) != NULL);

        check_order(table, &keys[i - 1], 5 - i);
    }

    CHECK(flow_table_insert(table, &keys[2]) == flow_table_find(table, &keys[2]));

    check_order(table, keys, 4);

    CHECK(flow_table_remove(table, &keys[1]) == 1);

    const struct flow_key after_middle[] = { keys[0], keys[2], keys[3] };

    check_order(table, after_middle, 3);

    CHECK(flow_table_remove(table, &keys[0]) == 1);

    check_order(table, &keys[2], 2);

    CHECK(flow_table_remove(table, &keys[3]) == 1);

    check_order(table, &keys[2], 1);

    CHECK(flow_table_remove(table, &keys[2]) == 1);

    check_order(table, keys, 0);

    CHECK(flow_table_insert(table, &keys[4]) != NULL);

    check_order(table, &keys[4], 1);

    flow_table_destroy(table);
}

static void test_touch_and_eviction(void) {
    struct flow_table *table = flow_table_create(1, 3);
    struct flow_key keys[5];
    struct flow_entry *entries[3];

    CHECK(table != NULL);

    for (size_t i = 0; i < 5; i++) {
        keys[i] = make_key(0xC6336401 + (uint32_t)i);
    }

    CHECK(flow_table_touch(table, &keys[0]) == NULL);

    for (size_t i = 0; i < 3; i++) {
        entries[i] = flow_table_insert(table, &keys[i]);

        CHECK(entries[i] != NULL);
    }

    const struct flow_key initial[] = { keys[2], keys[1], keys[0] };

    CHECK(flow_table_find(table, &keys[0]) == entries[0]);
    CHECK(flow_table_insert(table, &keys[0]) == entries[0]);
    CHECK(flow_table_touch(table, &keys[4]) == NULL);

    check_order(table, initial, 3);

    CHECK(flow_table_touch(table, &keys[0]) == entries[0]);

    const struct flow_key after_oldest[] = { keys[0], keys[2], keys[1] };

    check_order(table, after_oldest, 3);

    CHECK(flow_table_touch(table, &keys[2]) == entries[2]);
    CHECK(flow_table_touch(table, &keys[2]) == entries[2]);

    const struct flow_key after_middle[] = { keys[2], keys[0], keys[1] };

    check_order(table, after_middle, 3);

    CHECK(flow_table_insert(table, &keys[3]) != NULL);
    CHECK(flow_table_find(table, &keys[1]) == NULL);
    CHECK(flow_table_find(table, &keys[0]) == entries[0]);
    CHECK(flow_table_find(table, &keys[2]) == entries[2]);

    const struct flow_key after_eviction[] = { keys[3], keys[2], keys[0] };

    check_order(table, after_eviction, 3);

    CHECK(flow_table_insert(table, &keys[4]) != NULL);
    CHECK(flow_table_find(table, &keys[0]) == NULL);

    const struct flow_key after_second[] = { keys[4], keys[3], keys[2] };

    check_order(table, after_second, 3);

    flow_table_destroy(table);
}

static void test_capacity_one(void) {
    struct flow_table *table = flow_table_create(8, 1);
    struct flow_key previous = make_key(0xC6336401);

    CHECK(table != NULL);
    CHECK(flow_table_insert(table, &previous) != NULL);
    CHECK(flow_table_touch(table, &previous) != NULL);

    check_order(table, &previous, 1);

    for (uint32_t i = 2; i < 102; i++) {
        const struct flow_key key = make_key(0xC6336400 + i);

        CHECK(flow_table_insert(table, &key) != NULL);
        CHECK(flow_table_find(table, &previous) == NULL);

        check_order(table, &key, 1);

        previous = key;
    }

    CHECK(flow_table_remove(table, &previous) == 1);

    check_order(table, &previous, 0);

    CHECK(flow_table_insert(table, &previous) != NULL);

    check_order(table, &previous, 1);

    flow_table_destroy(table);
}

int main(void) {
    test_empty_and_invalid_sizes();
    test_duplicate_and_key_ownership();
    test_each_field_is_part_of_identity();
    test_padding_does_not_change_identity();
    test_collision_chain_removal();
    test_ten_thousand_keys();
    test_capacity_and_order();
    test_touch_and_eviction();
    test_capacity_one();

    puts("flow_table: ok");

    return 0;
}
