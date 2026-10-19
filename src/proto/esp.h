#ifndef PIGEON_PROTO_ESP_H
#define PIGEON_PROTO_ESP_H

#include <stddef.h>
#include <stdint.h>

#define ESP_HEADER_LEN 8
#define ESP_NATT_PORT 4500

struct esp_view {
    uint32_t spi;
    uint32_t sequence;
    const uint8_t *payload;
    size_t payload_len;
    size_t payload_wire_len;
    int udp_encapsulated;
};

/* Read the visible SPI/sequence header only, not encrypted inner addresses or
 * ports. The body includes protected data/trailer and any IV/authentication
 * overhead: it is not a decrypted application-payload count. Wire length must
 * include at least the header and mandatory two-byte trailer. A zero SPI is
 * reserved and rejected. Captured body truncation is allowed; header truncation
 * is not. Payload borrows data; out remains unchanged on failure (-1). */
int esp_parse(const uint8_t *data, size_t captured, size_t wire, struct esp_view *out);

#endif
