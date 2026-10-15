#!/usr/bin/env python3
"""Writes tcp_handshake.pcap: a TCP handshake plus one request/response.

Client 192.0.2.10:49152 -> server 198.51.100.20:80 (RFC 5737 addresses),
locally administered MACs, valid IPv4 and TCP checksums, no padding.
"""
import socket
import struct
import sys

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = socket.inet_aton("192.0.2.10")
SERVER_IP = socket.inet_aton("198.51.100.20")
CLIENT_PORT, SERVER_PORT = 49152, 80

SYN, ACK, PSH = 0x02, 0x10, 0x08


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(from_client, ident, seq, ack, flags, payload=b""):
    if from_client:
        smac, dmac, sip, dip = CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP
        sport, dport = CLIENT_PORT, SERVER_PORT
    else:
        smac, dmac, sip, dip = SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP
        sport, dport = SERVER_PORT, CLIENT_PORT

    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                      5 << 4, flags, 64240, 0, 0) + payload
    pseudo = sip + dip + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]

    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ident,
                     0x4000, 64, 6, 0, sip, dip)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]

    return dmac + smac + b"\x08\x00" + ip + tcp


def main(path):
    request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    c_isn, s_isn = 1000, 5000

    frames = [
        frame(True, 1, c_isn, 0, SYN),
        frame(False, 1, s_isn, c_isn + 1, SYN | ACK),
        frame(True, 2, c_isn + 1, s_isn + 1, ACK),
        frame(True, 3, c_isn + 1, s_isn + 1, PSH | ACK, request),
        frame(False, 2, s_isn + 1, c_isn + 1 + len(request),
              PSH | ACK, response),
    ]

    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            out.write(struct.pack("<IIII", 1700000000, i * 1000, len(f), len(f)))
            out.write(f)

    print([len(f) for f in frames])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tcp_handshake.pcap")
