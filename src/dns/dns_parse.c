#include "dns/dns_parse.h"

#include <string.h>

#include "proto/bytes.h"

#define DNS_HEADER_LEN 12
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_CNAME 5
#define DNS_CLASS_IN 1
#define DNS_NAME_STEPS 128
#define DNS_NAME_UNSUPPORTED 2

struct question {
    char name[DNS_NAME_LEN];
    uint16_t type;
    uint16_t class;
};

struct record {
    char owner[DNS_NAME_LEN];
    char target[DNS_NAME_LEN];
    uint16_t type;
    struct ip_addr ip;
    uint32_t ttl;
};

/* limit bounds the original field; a compression target uses message bounds. */
static int decode_name(const uint8_t *data, size_t len, size_t start, size_t limit,
                        char out[DNS_NAME_LEN], size_t *consumed) {
    size_t position = start;
    size_t end = limit;
    size_t written = 0;
    size_t wire_len = 1;
    size_t used = 0;
    int jumped = 0;

    for (unsigned step = 0; step < DNS_NAME_STEPS; step++) {
        if (position >= end) {
            return DNS_PARSE_PARTIAL;
        }

        const uint8_t label = data[position];

        if ((label & 0xC0) == 0xC0) {
            if (end - position < 2) {
                return DNS_PARSE_PARTIAL;
            }

            const size_t target = ((size_t)(label & 0x3F) << 8) | data[position + 1];

            if (target < DNS_HEADER_LEN || target >= position || target >= len) {
                return DNS_PARSE_INVALID;
            }

            if (!jumped) {
                used += 2;
            }

            jumped = 1;
            position = target;
            end = len;

            continue;
        }

        if ((label & 0xC0) != 0) {
            return DNS_PARSE_INVALID;
        }

        position++;

        if (!jumped) {
            used++;
        }

        if (label == 0) {
            if (written == 0) {
                out[written++] = '.';
            }

            out[written] = '\0';
            *consumed = used;

            return DNS_PARSE_OK;
        }

        if ((size_t)label > end - position) {
            return DNS_PARSE_PARTIAL;
        }

        wire_len += (size_t)label + 1;

        if (wire_len > 255) {
            return DNS_PARSE_INVALID;
        }

        if (written != 0) {
            out[written++] = '.';
        }

        for (size_t i = 0; i < label; i++) {
            uint8_t byte = data[position + i];

            if (byte < 33 || byte > 126 || byte == '.' || byte == '\\') {
                return DNS_NAME_UNSUPPORTED;
            }

            if (byte >= 'A' && byte <= 'Z') {
                byte = (uint8_t)(byte + ('a' - 'A'));
            }

            /* wire_len <= 255 bounds the dotted name to 253 bytes. */
            out[written++] = (char)byte;
        }

        if (!jumped) {
            used += label;
        }

        position += label;
    }

    return DNS_PARSE_INVALID;
}

static uint32_t minimum(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

static int resolve_question(const struct question *question,
                             const struct record *records, size_t count,
                             const char **name, uint32_t *ttl) {
    *name = question->name;
    *ttl = UINT32_MAX;

    for (size_t step = 0; step <= count; step++) {
        const struct record *alias = NULL;

        for (size_t i = 0; i < count; i++) {
            if (records[i].type == DNS_TYPE_CNAME &&
                strcmp(records[i].owner, *name) == 0) {
                alias = &records[i];
                break;
            }
        }

        if (alias == NULL) {
            return DNS_PARSE_OK;
        }

        *name = alias->target;
        *ttl = minimum(*ttl, alias->ttl);
    }

    return DNS_PARSE_INVALID;
}

static int emit_answers(const struct record *records, size_t record_count,
                         const struct question *questions, size_t question_count,
                         struct dns_answer *out, size_t capacity, size_t *count) {
    const char *resolved[DNS_MAX_QUESTIONS];
    uint32_t ttls[DNS_MAX_QUESTIONS];
    int status = DNS_PARSE_OK;

    for (size_t q = 0; q < question_count; q++) {
        if (resolve_question(&questions[q], records, record_count,
                              &resolved[q], &ttls[q]) == DNS_PARSE_INVALID) {
            resolved[q] = NULL;
            status = DNS_PARSE_INVALID;
        }
    }

    for (size_t i = 0; i < record_count; i++) {
        if (records[i].type == DNS_TYPE_CNAME) {
            struct question source = { 0 };
            const char *target;
            uint32_t ttl;

            memcpy(source.name, records[i].owner, strlen(records[i].owner) + 1);

            if (resolve_question(&source, records, record_count, &target, &ttl)
                == DNS_PARSE_INVALID) {
                status = DNS_PARSE_INVALID;
            }
        }
    }

    for (size_t i = 0; i < record_count; i++) {
        if (records[i].type != DNS_TYPE_A && records[i].type != DNS_TYPE_AAAA) {
            continue;
        }

        struct dns_answer answer = { .ip = records[i].ip, .ttl = records[i].ttl };
        const char *name = records[i].owner;

        for (size_t q = 0; q < question_count; q++) {
            if (questions[q].class == DNS_CLASS_IN &&
                (questions[q].type == records[i].type || questions[q].type == 255) &&
                resolved[q] != NULL && strcmp(resolved[q], records[i].owner) == 0) {
                name = questions[q].name;
                answer.ttl = minimum(answer.ttl, ttls[q]);
                break;
            }
        }

        if (*count == capacity) {
            return status == DNS_PARSE_INVALID ? status : DNS_PARSE_PARTIAL;
        }

        memcpy(answer.name, name, strlen(name) + 1);
        out[(*count)++] = answer;
    }

    return status;
}

int dns_parse_response(const uint8_t *data, size_t len,
                       struct dns_answer *out, size_t capacity, size_t *count) {
    *count = 0;

    if (len < DNS_HEADER_LEN) {
        return DNS_PARSE_PARTIAL;
    }

    const uint16_t flags = be16(data + 2);

    if ((flags & 0x8000) == 0 || (flags & 0x780F) != 0) {
        return DNS_PARSE_OK;
    }

    const size_t question_count = be16(data + 4);
    const size_t answer_count = be16(data + 6);

    if (question_count > DNS_MAX_QUESTIONS) {
        return DNS_PARSE_PARTIAL;
    }

    struct question questions[DNS_MAX_QUESTIONS];
    struct record records[DNS_MAX_ANSWERS];

    size_t offset = DNS_HEADER_LEN;
    size_t record_count = 0;
    int status = (flags & 0x0200) != 0 ? DNS_PARSE_PARTIAL : DNS_PARSE_OK;

    for (size_t q = 0; q < question_count; q++) {
        size_t consumed;
        const int rc = decode_name(data, len, offset, len, questions[q].name, &consumed);

        if (rc != DNS_PARSE_OK) {
            return rc == DNS_NAME_UNSUPPORTED ? DNS_PARSE_PARTIAL : rc;
        }

        offset += consumed;

        if (len - offset < 4) {
            return DNS_PARSE_PARTIAL;
        }

        questions[q].type = be16(data + offset);
        questions[q].class = be16(data + offset + 2);
        offset += 4;
    }

    for (size_t a = 0; a < answer_count; a++) {
        if (a == DNS_MAX_ANSWERS) {
            status = DNS_PARSE_PARTIAL;
            break;
        }

        struct record record = { 0 };
        size_t consumed;
        const int rc = decode_name(data, len, offset, len, record.owner, &consumed);

        if (rc != DNS_PARSE_OK) {
            status = rc == DNS_NAME_UNSUPPORTED ? DNS_PARSE_PARTIAL : rc;
            break;
        }

        offset += consumed;

        if (len - offset < 10) {
            status = DNS_PARSE_PARTIAL;
            break;
        }

        record.type = be16(data + offset);
        const uint16_t class = be16(data + offset + 2);
        const uint32_t wire_ttl = be32(data + offset + 4);
        const size_t rdlength = be16(data + offset + 8);

        record.ttl = wire_ttl > INT32_MAX ? 0 : wire_ttl;
        offset += 10;

        if (rdlength > len - offset) {
            status = DNS_PARSE_PARTIAL;
            break;
        }

        if (class == DNS_CLASS_IN && (record.type == DNS_TYPE_A || record.type == DNS_TYPE_AAAA)) {
            const size_t address_len = record.type == DNS_TYPE_A ? 4 : 16;

            if (rdlength != address_len) {
                status = DNS_PARSE_INVALID;
                break;
            }

            record.ip.family = record.type == DNS_TYPE_A ? 4 : 6;
            memcpy(record.ip.bytes, data + offset, address_len);
            records[record_count++] = record;
        } else if (class == DNS_CLASS_IN && record.type == DNS_TYPE_CNAME) {
            const int name_rc = decode_name(data, len, offset, offset + rdlength,
                                             record.target, &consumed);

            if (name_rc != DNS_PARSE_OK || consumed != rdlength) {
                status = name_rc == DNS_NAME_UNSUPPORTED ? DNS_PARSE_PARTIAL
                         : name_rc == DNS_PARSE_PARTIAL ? DNS_PARSE_INVALID : name_rc;

                if (status == DNS_PARSE_OK) {
                    status = DNS_PARSE_INVALID;
                }

                break;
            }

            records[record_count++] = record;
        }

        offset += rdlength;
    }

    const int emitted = emit_answers(records, record_count, questions, question_count,
                                      out, capacity, count);

    if (status == DNS_PARSE_INVALID || emitted == DNS_PARSE_INVALID) {
        return DNS_PARSE_INVALID;
    }

    return status == DNS_PARSE_PARTIAL || emitted == DNS_PARSE_PARTIAL
           ? DNS_PARSE_PARTIAL : DNS_PARSE_OK;
}
