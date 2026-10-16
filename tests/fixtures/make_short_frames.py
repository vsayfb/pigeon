#!/usr/bin/env python3
"""Writes short_frames.pcap: minimum-size Ethernet frames carrying padding.

Ethernet needs at least 60 bytes (without the FCS), so a sender pads shorter
frames with zeros. The padding is not part of the IP packet: IP total_len
stops before it. Four frames, all 60 bytes on the wire:

  1. TCP pure ACK, client -> server       (padding 6,  TCP payload 0)
  2. TCP pure ACK, server -> client       (padding 6,  TCP payload 0)
  3. TCP PSH|ACK with 1 payload byte      (padding 5,  TCP payload 1)
  4. UDP with 1 payload byte              (padding 17, UDP payload 1)

Same addresses and ports as make_tcp_handshake.py (RFC 5737, fake MACs,
valid IPv4/TCP/UDP checksums).
"""
import socket
import struct
import sys

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = socket.inet_aton("192.0.2.10")
SERVER_IP = socket.inet_aton("198.51.100.20")
CLIENT_PORT, SERVER_PORT = 49152, 80

ACK, PSH = 0x10, 0x08
MIN_FRAME = 60


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ip_packet(proto, sip, dip, ident, l4):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), ident,
                     0x4000, 64, proto, 0, sip, dip)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return ip + l4


def ethernet(dmac, smac, packet):
    frame = dmac + smac + b"\x08\x00" + packet
    return frame + b"\x00" * max(0, MIN_FRAME - len(frame))   # zero padding


def tcp_frame(from_client, ident, seq, ack, flags, payload=b""):
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
    return ethernet(dmac, smac, ip_packet(6, sip, dip, ident, tcp))


def udp_frame(ident, payload):
    udp = struct.pack("!HHHH", CLIENT_PORT, 9999, 8 + len(payload), 0) + payload
    pseudo = CLIENT_IP + SERVER_IP + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    return ethernet(SERVER_MAC, CLIENT_MAC,
                    ip_packet(17, CLIENT_IP, SERVER_IP, ident, udp))


def main(path):
    frames = [
        tcp_frame(True, 1, 1001, 5001, ACK),
        tcp_frame(False, 1, 5001, 1001, ACK),
        tcp_frame(True, 2, 1001, 5001, PSH | ACK, b"x"),
        udp_frame(3, b"y"),
    ]

    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, f in enumerate(frames):
            out.write(struct.pack("<IIII", 1700000000, i * 1000, len(f), len(f)))
            out.write(f)

    print([len(f) for f in frames])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "short_frames.pcap")
