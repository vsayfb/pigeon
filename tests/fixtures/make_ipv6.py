#!/usr/bin/env python3
"""Synthetic IPv6 TCP/UDP, extensions, AAAA naming, and a short capture."""

from pathlib import Path
import socket
import struct

from dns_fixture import checksum, name

CLIENT = socket.inet_pton(socket.AF_INET6, "2001:db8::10")
SERVER = socket.inet_pton(socket.AF_INET6, "2001:db8:1::42")
RESOLVER = socket.inet_pton(socket.AF_INET6, "2001:db8::53")


def frame(protocol, remote, incoming, payload, extension=None):
    src, dst = (remote, CLIENT) if incoming else (CLIENT, remote)
    service_port = 53 if remote == RESOLVER else 443
    sport, dport = (service_port, 49152) if incoming else (49152, service_port)

    if protocol == 17:
        transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        checksum_offset = 6
    else:
        transport = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 0x50, 0x18,
                                65535, 0, 0) + payload
        checksum_offset = 16

    pseudo = src + dst + struct.pack("!I3xB", len(transport), protocol)
    value = checksum(pseudo + transport) or 0xFFFF
    transport = transport[:checksum_offset] + struct.pack("!H", value) + transport[checksum_offset + 2:]
    extensions = bytes([protocol, 0]) + bytes(6) if extension is not None else b""
    ip = struct.pack("!IHBB16s16s", 6 << 28, len(extensions) + len(transport),
                     protocol if extension is None else extension, 64, src, dst)
    mac1 = bytes.fromhex("020000000001")
    mac2 = bytes.fromhex("020000000002")
    src_mac, dst_mac = (mac2, mac1) if incoming else (mac1, mac2)

    return dst_mac + src_mac + b"\x86\xdd" + ip + extensions + transport


def main(path):
    question = name("www.v6.example.test") + struct.pack("!HH", 28, 1)
    query = struct.pack("!HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0) + question
    reply = bytearray(struct.pack("!HHHHHH", 0x5678, 0x8180, 1, 2, 0, 0) + question)
    target = name("edge.v6.example.test")
    reply.extend(b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)))
    target_offset = len(reply)
    reply.extend(target)
    reply.extend(struct.pack("!HHHIH", 0xC000 | target_offset, 28, 1, 120, 16) + SERVER)
    frames = [
        frame(17, RESOLVER, False, query),
        frame(6, SERVER, False, b"hello", 0),
        frame(17, RESOLVER, True, bytes(reply), 60),
        frame(6, SERVER, True, b"world!"),
        frame(17, SERVER, False, b"x"),
        frame(6, SERVER, False, b"0123456789"),
    ]

    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        for i, data in enumerate(frames):
            captured = data[:-7] if i == len(frames) - 1 else data
            out.write(struct.pack("<IIII", 1700000000 + i, 0, len(captured), len(data)))
            out.write(captured)


if __name__ == "__main__":
    main(Path(__file__).with_name("ipv6_conversations.pcap"))
