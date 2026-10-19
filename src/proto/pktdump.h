#ifndef PIGEON_PROTO_PKTDUMP_H
#define PIGEON_PROTO_PKTDUMP_H

#include <stdio.h>
#include "proto/packet.h"

/* Prints a successfully decoded packet to stream. Does not retain packet. */
void pktdump(FILE *stream, const struct packet_view *packet);

#endif
