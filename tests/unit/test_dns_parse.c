#include <string.h>

#include "../t.h"
#include "capture/capture.h"
#include "dns/dns_parse.h"
#include "proto/packet.h"

struct message {
    uint8_t data[4096];
    size_t len;
};

static void put16(struct message *m, unsigned value) {
    m->data[m->len++] = (uint8_t)(value >> 8);
    m->data[m->len++] = (uint8_t)value;
}

static void put32(struct message *m, uint32_t value) {
    put16(m, value >> 16);
    put16(m, value & 0xFFFF);
}

static void put_name(struct message *m, const char *name) {
    while (*name != '\0') {
        const char *dot = strchr(name, '.');
        const size_t length = dot == NULL ? strlen(name) : (size_t)(dot - name);

        m->data[m->len++] = (uint8_t)length;
        memcpy(m->data + m->len, name, length);
        m->len += length;

        if (dot == NULL) {
            break;
        }

        name = dot + 1;
    }

    m->data[m->len++] = 0;
}

static struct message begin_message(unsigned answers) {
    struct message m = { .data = { 0x12, 0x34, 0x81, 0x80, 0, 1 }, .len = 12 };

    m.data[6] = (uint8_t)(answers >> 8);
    m.data[7] = (uint8_t)answers;
    put_name(&m, "WWW.Example.TEST");
    put16(&m, 1);
    put16(&m, 1);

    return m;
}

static void put_a(struct message *m, const char *owner, uint32_t ip, uint32_t ttl) {
    put_name(m, owner);
    put16(m, 1);
    put16(m, 1);
    put32(m, ttl);
    put16(m, 4);
    put32(m, ip);
}

static void put_cname(struct message *m, const char *owner, const char *target, uint32_t ttl) {
    put_name(m, owner);
    put16(m, 5);
    put16(m, 1);
    put32(m, ttl);

    const size_t length_offset = m->len;

    put16(m, 0);

    const size_t start = m->len;

    put_name(m, target);
    m->data[length_offset + 1] = (uint8_t)(m->len - start);
}

static void test_a_records_and_output_limits(void) {
    struct message m = begin_message(2);
    struct dns_answer out[2];
    size_t count;

    put_a(&m, "www.example.test", 0xC633642A, 300);
    put_a(&m, "www.example.test", 0xC633642B, 400);

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_OK);
    CHECK(count == 2);
    CHECK(out[0].ip == 0xC633642A);
    CHECK(out[1].ip == 0xC633642B);
    CHECK(out[0].ttl == 300);
    CHECK(strcmp(out[0].name, "www.example.test") == 0);
    CHECK(dns_parse_response(m.data, m.len, NULL, 0, &count) == DNS_PARSE_PARTIAL);
    CHECK(count == 0);

    memset(&out[1], 0xAB, sizeof out[1]);
    unsigned char before[sizeof out[1]];

    memcpy(before, &out[1], sizeof before);

    CHECK(dns_parse_response(m.data, m.len, out, 1, &count) == DNS_PARSE_PARTIAL);
    CHECK(count == 1);
    CHECK(memcmp(before, &out[1], sizeof before) == 0);

    m.data[2] |= 2;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_PARTIAL);
    CHECK(count == 2);

    m.data[2] = 1;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_OK);
    CHECK(count == 0);

    m.data[2] = 0x81;
    m.data[3] = 0x83;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_OK);
    CHECK(count == 0);
}

static void test_cname_chain_and_cycle(void) {
    struct message m = begin_message(3);
    struct dns_answer out[2];
    size_t count;

    /* A records may precede the CNAME records they satisfy. */
    put_a(&m, "origin.example.test", 0xC633642A, 300);
    put_cname(&m, "edge.example.test", "origin.example.test", 120);
    put_cname(&m, "www.example.test", "edge.example.test", 60);

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_OK);
    CHECK(count == 1);
    CHECK(strcmp(out[0].name, "www.example.test") == 0);
    CHECK(out[0].ttl == 60);

    m = begin_message(2);
    put_cname(&m, "www.example.test", "edge.example.test", 60);
    put_cname(&m, "edge.example.test", "www.example.test", 60);

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);

    m = begin_message(3);
    put_a(&m, "other.example.test", 0xC633642A, 300);
    put_cname(&m, "www.example.test", "edge.example.test", 60);
    put_cname(&m, "edge.example.test", "www.example.test", 60);

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);
    CHECK(count == 1);
    CHECK(strcmp(out[0].name, "other.example.test") == 0);

    m = (struct message){ .data = { 0x12, 0x34, 0x81, 0x80, 0, 0, 0, 2 }, .len = 12 };
    put_cname(&m, "www.example.test", "edge.example.test", 60);
    put_cname(&m, "edge.example.test", "www.example.test", 60);

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);
}

static void test_truncation_and_malformed_tail(void) {
    struct message m = begin_message(2);
    struct dns_answer out[2];
    size_t count;

    put_a(&m, "www.example.test", 0xC633642A, 300);

    const size_t first_end = m.len;

    put_a(&m, "www.example.test", 0xC633642B, 400);

    for (size_t len = 0; len < m.len; len++) {
        CHECK(dns_parse_response(m.data, len, out, 2, &count) == DNS_PARSE_PARTIAL);
        CHECK(count == (len >= first_end ? 1 : 0));
    }

    m.data[m.len - 5] = 3;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);
    CHECK(count == 1);
    CHECK(out[0].ip == 0xC633642A);
}

static void test_bad_names_and_lengths(void) {
    struct message m = begin_message(0);
    struct dns_answer out[2];
    size_t count;

    m.data[12] = 0xC0;
    m.data[13] = 12;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);

    m.data[13] = 14;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);

    m.data[13] = 0;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);

    m.data[12] = 0xFF;
    m.data[13] = 0xFF;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);

    m.data[12] = 0x40;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);

    m = begin_message(0);
    m.data[13] = 0;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_PARTIAL);

    m = begin_message(1);
    put_name(&m, "www.example.test");
    put16(&m, 5);
    put16(&m, 1);
    put32(&m, 60);
    put16(&m, 1);
    m.data[m.len++] = 0xC0;

    CHECK(dns_parse_response(m.data, m.len, out, 2, &count) == DNS_PARSE_INVALID);
}

static void test_limits_and_unknown_records(void) {
    struct message m = begin_message(65);
    struct dns_answer out[DNS_MAX_ANSWERS];
    size_t count;

    for (unsigned i = 0; i < 65; i++) {
        put16(&m, 0xC00C);
        put16(&m, 1);
        put16(&m, 1);
        put32(&m, 30);
        put16(&m, 4);
        put32(&m, 0xC6336401 + i);
    }

    CHECK(dns_parse_response(m.data, m.len, out, DNS_MAX_ANSWERS, &count)
          == DNS_PARSE_PARTIAL);
    CHECK(count == DNS_MAX_ANSWERS);

    m.data[5] = DNS_MAX_QUESTIONS + 1;

    CHECK(dns_parse_response(m.data, m.len, out, DNS_MAX_ANSWERS, &count)
          == DNS_PARSE_PARTIAL);
    CHECK(count == 0);

    m = begin_message(2);
    put_name(&m, "www.example.test");
    put16(&m, 28);
    put16(&m, 1);
    put32(&m, 300);
    put16(&m, 16);
    memset(m.data + m.len, 0xAA, 16);
    m.len += 16;
    put_a(&m, "other.example.test", 0xC633642A, UINT32_MAX);

    CHECK(dns_parse_response(m.data, m.len, out, DNS_MAX_ANSWERS, &count) == DNS_PARSE_OK);
    CHECK(count == 1);
    CHECK(strcmp(out[0].name, "other.example.test") == 0);
    CHECK(out[0].ttl == 0);
}

static void test_maximum_name(void) {
    struct message m = { .data = { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1 }, .len = 12 };
    struct dns_answer out;
    size_t count;

    for (unsigned i = 0; i < 4; i++) {
        const size_t length = i == 3 ? 61 : 63;

        m.data[m.len++] = (uint8_t)length;
        memset(m.data + m.len, 'a', length);
        m.len += length;
    }

    m.data[m.len++] = 0;
    put16(&m, 1);
    put16(&m, 1);
    put16(&m, 0xC00C);
    put16(&m, 1);
    put16(&m, 1);
    put32(&m, 30);
    put16(&m, 4);
    put32(&m, 0xC633642A);

    CHECK(dns_parse_response(m.data, m.len, &out, 1, &count) == DNS_PARSE_OK);
    CHECK(count == 1);
    CHECK(strlen(out.name) == 253);
}

struct replay {
    unsigned packets;
    unsigned replies;
};

static void check_fixture(const uint8_t *data, uint32_t caplen, uint32_t wirelen,
                           int64_t timestamp, void *user) {
    struct replay *replay = user;
    struct packet_view packet;
    struct dns_answer out[4];
    size_t count;

    (void)wirelen;
    (void)timestamp;

    CHECK(packet_parse(data, caplen, &packet) == 0);
    CHECK(packet.kind == PACKET_UDP);
    CHECK(dns_parse_response(packet.transport.udp.payload, packet.transport.udp.payload_len,
                            out, 4, &count) == DNS_PARSE_OK);

    replay->packets++;

    if (packet.transport.udp.src_port == 53) {
        CHECK(count == 1);
        CHECK(out[0].ip == 0xC633642A);
        CHECK(out[0].ttl == 60);
        CHECK(strcmp(out[0].name, "www.example.test") == 0);

        replay->replies++;
    } else {
        CHECK(count == 0);
    }
}

static void test_fixtures(void) {
    struct replay plain = { 0 };
    struct replay compressed = { 0 };

    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/dns_a_record.pcap", check_fixture, &plain) == 0);
    CHECK(capture_run_file(PIGEON_FIXTURE_DIR "/dns_compressed.pcap", check_fixture, &compressed) == 0);
    CHECK(plain.packets == 2 && plain.replies == 1);
    CHECK(compressed.packets == 2 && compressed.replies == 1);
}

int main(void) {
    test_a_records_and_output_limits();
    test_cname_chain_and_cycle();
    test_truncation_and_malformed_tail();
    test_bad_names_and_lengths();
    test_limits_and_unknown_records();
    test_maximum_name();
    test_fixtures();

    puts("dns_parse: ok");

    return 0;
}
