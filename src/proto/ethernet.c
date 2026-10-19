#include "proto/ethernet.h"

#include <string.h>

#include "proto/bytes.h"

int eth_parse(const uint8_t *frame, const size_t len, struct eth_view *out) {
    if (len < ETH_HEADER_LEN) {
        return -1;
    }

    struct eth_view eth = { 0 };

    memcpy(eth.dst, frame, ETH_ADDR_LEN);
    memcpy(eth.src, frame + ETH_ADDR_LEN, ETH_ADDR_LEN);
    eth.ethertype = be16(frame + 2 * ETH_ADDR_LEN);

    size_t offset = ETH_HEADER_LEN;

    while (eth.ethertype == ETHERTYPE_VLAN || eth.ethertype == ETHERTYPE_VLAN_SERVICE) {
        if (eth.vlan_count == ETH_MAX_VLAN_TAGS || len - offset < 4) {
            return -1;
        }

        struct vlan_tag *tag = &eth.vlans[eth.vlan_count++];

        tag->tpid = eth.ethertype;
        tag->tci = be16(frame + offset);
        eth.ethertype = be16(frame + offset + 2);
        offset += 4;
    }

    eth.payload = frame + offset;
    eth.payload_len = len - offset;
    *out = eth;

    return 0;
}
