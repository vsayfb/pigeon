#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns/dns_parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct dns_answer answers[DNS_MAX_ANSWERS + 1];
    const size_t capacity = size == 0 ? 0 : data[0] % (DNS_MAX_ANSWERS + 1);
    size_t count = SIZE_MAX;

    memset(answers, 0xAB, sizeof answers);

    const int rc = dns_parse_response(data, size, answers, capacity, &count);

    if (rc < DNS_PARSE_INVALID || rc > DNS_PARSE_PARTIAL || count > capacity) {
        abort();
    }

    for (size_t i = 0; i < count; i++) {
        if (memchr(answers[i].name, '\0', DNS_NAME_LEN) == NULL ||
            answers[i].ttl > INT32_MAX) {
            abort();
        }
    }

    const unsigned char *untouched = (const unsigned char *)&answers[count];
    const size_t remaining = (DNS_MAX_ANSWERS + 1 - count) * sizeof answers[0];

    unsigned char guard[sizeof answers];

    memset(guard, 0xAB, sizeof guard);

    if (memcmp(untouched, guard, remaining) != 0) {
        abort();
    }

    if (dns_parse_response(data, size, NULL, 0, &count) < DNS_PARSE_INVALID || count != 0) {
        abort();
    }

    return 0;
}

#ifndef DNS_LIBFUZZER
#define FUZZ_BUFFER_LEN 65535

static uint32_t random_state = UINT32_C(0x50494745);

static uint32_t next_random(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;

    return random_state;
}

int main(int argc, char **argv) {
    unsigned long iterations = 100000;

    if (argc > 1) {
        char *end;

        iterations = strtoul(argv[1], &end, 10);

        if (*end != '\0' || iterations == 0) {
            return 2;
        }
    }

    uint8_t seed[FUZZ_BUFFER_LEN] = {
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
        1, 'a', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1,
        0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 198, 51, 100, 42
    };

    size_t seed_len = 40;
    uint8_t buffer[FUZZ_BUFFER_LEN];

    if (argc > 2) {
        FILE *file = fopen(argv[2], "rb");

        if (file == NULL) {
            perror("fuzz seed");

            return 1;
        }

        seed_len = fread(seed, 1, sizeof seed, file);

        if (ferror(file)) {
            fclose(file);

            return 1;
        }

        fclose(file);
    }

    LLVMFuzzerTestOneInput(seed, seed_len);

    for (unsigned long run = 0; run < iterations; run++) {
        size_t len;

        if (next_random() % 4 == 0) {
            len = next_random() % 1024;

            for (size_t i = 0; i < len; i++) {
                buffer[i] = (uint8_t)next_random();
            }
        } else {
            len = seed_len;
            memcpy(buffer, seed, len);

            const unsigned mutations = 1 + next_random() % 8;

            for (unsigned i = 0; i < mutations && len != 0; i++) {
                buffer[next_random() % len] = (uint8_t)next_random();
            }

            if (next_random() % 4 == 0) {
                len = next_random() % (len + 1);
            }
        }

        LLVMFuzzerTestOneInput(buffer, len);
    }

    printf("dns fuzz: %lu inputs checked\n", iterations);

    return 0;
}
#endif
