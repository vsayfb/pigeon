#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proto/packet.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct packet_view packet;
    unsigned char before[sizeof packet];

    memset(&packet, 0xAB, sizeof packet);
    memcpy(before, &packet, sizeof packet);

    const int rc = packet_parse(data, size, &packet);

    if (rc == -1) {
        if (memcmp(before, &packet, sizeof packet) != 0) {
            abort();
        }

        return 0;
    }

    if (rc != 0 || packet.eth.payload < data || packet.eth.payload > data + size ||
        packet.eth.payload_len > size - (size_t)(packet.eth.payload - data)) {
        abort();
    }

    if (packet.kind == PACKET_TCP || packet.kind == PACKET_UDP) {
        const uint8_t *payload = packet.kind == PACKET_TCP
                                 ? packet.transport.tcp.payload : packet.transport.udp.payload;
        const size_t readable = packet.kind == PACKET_TCP
                                ? packet.transport.tcp.payload_len : packet.transport.udp.payload_len;
        const size_t wire = packet.kind == PACKET_TCP
                            ? packet.transport.tcp.payload_wire_len : packet.transport.udp.payload_wire_len;

        if (payload < data || payload > data + size ||
            readable > size - (size_t)(payload - data) || readable > wire) {
            abort();
        }
    }

    if (packet.kind == PACKET_ICMP || packet.kind == PACKET_ICMPV6) {
        const struct icmp_view *icmp = &packet.transport.icmp;

        if (icmp->payload < data || icmp->payload > data + size ||
            icmp->payload_len > size - (size_t)(icmp->payload - data) ||
            icmp->payload_len > icmp->payload_wire_len) {
            abort();
        }
    }

    return 0;
}

#ifndef PACKET_LIBFUZZER
static uint32_t state = UINT32_C(0x70696736);

static uint32_t random_value(void) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;

    return state;
}

int main(int argc, char **argv) {
    const unsigned long iterations = argc > 1 ? strtoul(argv[1], NULL, 10) : 100000;
    uint8_t seed[65535] = { [12] = 0x86, [13] = 0xDD, [14] = 0x60,
                           [19] = 20, [20] = 6, [66] = 0x50 };
    uint8_t buffer[65535];
    size_t seed_len = 74;

    if (argc > 2) {
        FILE *file = fopen(argv[2], "rb");

        if (file == NULL) {
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

    for (unsigned long i = 0; i < iterations; i++) {
        size_t size = seed_len;

        if (random_value() % 4 == 0) {
            size = random_value() % 2048;

            for (size_t j = 0; j < size; j++) {
                buffer[j] = (uint8_t)random_value();
            }
        } else {
            memcpy(buffer, seed, size);

            const unsigned changes = 1 + random_value() % 12;

            for (unsigned j = 0; j < changes && size != 0; j++) {
                buffer[random_value() % size] = (uint8_t)random_value();
            }

            if (random_value() % 4 == 0) {
                size = random_value() % (size + 1);
            }
        }

        LLVMFuzzerTestOneInput(buffer, size);
    }

    printf("packet fuzz: %lu inputs checked\n", iterations);

    return 0;
}
#endif
