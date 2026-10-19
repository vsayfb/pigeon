#include "proto/esp.h"

#include "proto/bytes.h"

int esp_parse(const uint8_t *data, size_t captured, size_t wire, struct esp_view *out) {
    if (captured < ESP_HEADER_LEN || wire < ESP_HEADER_LEN + 2 || be32(data) == 0) {
        return -1;
    }

    const size_t end = captured < wire ? captured : wire;
    const struct esp_view esp = {
        .spi = be32(data),
        .sequence = be32(data + 4),
        .payload = data + ESP_HEADER_LEN,
        .payload_len = end - ESP_HEADER_LEN,
        .payload_wire_len = wire - ESP_HEADER_LEN
    };

    *out = esp;

    return 0;
}
