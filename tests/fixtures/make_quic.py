#!/usr/bin/env python3
"""Synthetic QUIC header evidence (v1/v2); encrypted bodies are opaque test bytes."""
from pathlib import Path
import ipaddress
import struct
import sys

sys.dont_write_bytecode = True

from make_icmp import checksum


def long_header(version, initial, destination, source):
    v2 = version == 0x6b3343cf
    kind = (1 if v2 else 0) if initial else (3 if v2 else 2)
    header = struct.pack('!BI', 0xc0 | kind << 4, version)
    header += bytes([len(destination)]) + destination + bytes([len(source)]) + source
    if initial:
        header += b'\0'  # token length
    size = 1200 if initial else 80
    body_size = size - len(header) - 2
    return header + struct.pack('!H', 0x4000 | body_size) + bytes(body_size)


def frame(ipv6, incoming, payload, peer, port):
    local = '2001:db8::10' if ipv6 else '192.0.2.10'
    source, destination = (peer, local) if incoming else (local, peer)
    source = ipaddress.ip_address(source).packed
    destination = ipaddress.ip_address(destination).packed
    ports = (port, 49152) if incoming else (49152, port)
    udp = struct.pack('!HHHH', *ports, len(payload) + 8, 0) + payload
    pseudo = source + destination + (struct.pack('!I3xB', len(udp), 17) if ipv6 else struct.pack('!BBH', 0, 17, len(udp)))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 0xffff) + udp[8:]
    if ipv6:
        ip = struct.pack('!IHBB', 6 << 28, len(udp), 17, 64) + source + destination
    else:
        ip = struct.pack('!BBHHHBBH', 0x45, 0, len(udp) + 20, 0, 0, 64, 17, 0) + source + destination
        ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return bytes.fromhex('020000000002020000000001') + struct.pack('!H', 0x86dd if ipv6 else 0x0800) + ip + udp


def write(path):
    frames = []
    for ipv6, version, peer, port in [(False, 1, '198.51.100.42', 8443),
                                       (True, 0x6b3343cf, '2001:db8::42', 443)]:
        frames.append(frame(ipv6, False, long_header(version, True, b'server00', b'client00'), peer, port))
        frames.append(frame(ipv6, True, long_header(version, False, b'client00', b'server01'), peer, port))
        frames.append(frame(ipv6, False, b'\x40' + bytes(49), peer, port))
    # Neither UDP/443 nor a short-looking first byte alone is evidence.
    frames.append(frame(False, False, b'not quic', '198.51.100.99', 443))
    frames.append(frame(False, False, b'\x40' + bytes(49), '198.51.100.100', 443))
    with Path(path).open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(frames):
            output.write(struct.pack('<IIII', 1700000000 + index, 0, len(packet), len(packet)))
            output.write(packet)


if __name__ == '__main__':
    write(Path(__file__).with_name('quic_conversations.pcap'))
