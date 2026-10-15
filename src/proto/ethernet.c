#include "proto/ethernet.h"

#include <string.h>

#include "proto/bytes.h"

int eth_parse(const uint8_t *frame, const size_t len, struct eth_view *out) {
    if (len < ETH_HEADER_LEN) {
        return -1;
    }

    memcpy(out->dst, frame, ETH_ADDR_LEN);
    memcpy(out->src, frame + ETH_ADDR_LEN, ETH_ADDR_LEN);
    out->ethertype = be16(frame + 2 * ETH_ADDR_LEN);
    out->payload = frame + ETH_HEADER_LEN;
    out->payload_len = len - ETH_HEADER_LEN;

    return 0;
}
