#ifndef PIGEON_DNS_PARSE_H
#define PIGEON_DNS_PARSE_H

#include <stddef.h>
#include <stdint.h>
#include "proto/address.h"

#define DNS_NAME_LEN 254
#define DNS_MAX_QUESTIONS 16
#define DNS_MAX_ANSWERS 64

struct dns_answer {
    struct ip_addr ip;
    uint32_t ttl;              /* seconds, minimum across the CNAME chain */
    char name[DNS_NAME_LEN];   /* lowercase ASCII, no trailing dot */
};

enum dns_parse_status {
    DNS_PARSE_INVALID = -1,
    DNS_PARSE_OK = 0,
    DNS_PARSE_PARTIAL = 1
};

/*
 * Decodes IN-class A/AAAA records from a DNS response's answer section. data is
 * the DNS message itself, without UDP headers; len is its readable length.
 * CNAME chains select the matching question's name, or the address record owner
 * when no question matches. Authority/additional sections are not inspected.
 * Queries, nonstandard opcodes and nonzero response codes yield no results.
 * Names use printable ASCII labels excluding literal dot and backslash;
 * binary labels require presentation escaping and are not supported here.
 * Compression pointers must refer backward within the message. Name walks,
 * questions, and answers are bounded. Only complete records become results.
 *
 * out provides capacity entries; NULL is valid only with capacity zero.
 * count receives the number written on every return. Entries own their names
 * and borrow no input bytes. No entries beyond count are modified.
 *
 * Returns DNS_PARSE_OK on completion, DNS_PARSE_PARTIAL for truncation, the
 * TC flag, unsupported label text or resource/output limits, and
 * DNS_PARSE_INVALID for malformed names, lengths or CNAME cycles. Complete
 * results preceding a later incomplete or malformed answer remain available
 * even on nonzero returns. Header/question failures produce zero results.
 */
int dns_parse_response(const uint8_t *data, size_t len,
                       struct dns_answer *out, size_t capacity, size_t *count);

#endif
