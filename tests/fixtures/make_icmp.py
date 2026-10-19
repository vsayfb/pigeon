#!/usr/bin/env python3
"""Generate deterministic ICMP/ICMPv6 peer traffic, errors and local controls."""
from pathlib import Path
import ipaddress
import struct


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def frame(ipv6, incoming, kind, code=0, body=b'ping', remote=None):
    local = '2001:db8::10' if ipv6 else '192.0.2.10'
    peer = remote or ('2001:db8::42' if ipv6 else '198.51.100.42')
    source, destination = (peer, local) if incoming else (local, peer)
    source = ipaddress.ip_address(source).packed
    destination = ipaddress.ip_address(destination).packed
    protocol = 58 if ipv6 else 1
    message = struct.pack('!BBHHH', kind, code, 0, 42, 1) + body
    pseudo = source + destination + struct.pack('!I3xB', len(message), protocol) if ipv6 else b''
    message = message[:2] + struct.pack('!H', checksum(pseudo + message)) + message[4:]
    if ipv6:
        header = struct.pack('!IHBB', 6 << 28, len(message), protocol, 64) + source + destination
    else:
        header = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(message), 0, 0, 64, protocol, 0) + source + destination
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    ethernet = bytes.fromhex('020000000002020000000001') + struct.pack('!H', 0x86dd if ipv6 else 0x0800)
    return ethernet + header + message


def write(path):
    quoted4 = frame(False, False, 8)[14:]
    quoted6 = frame(True, False, 128)[14:]
    frames = [frame(False, False, 8), frame(False, True, 0),
              frame(False, True, 11, body=quoted4, remote='198.51.100.1'),
              frame(True, False, 128), frame(True, True, 129),
              frame(True, True, 3, body=quoted6, remote='2001:db8::1'),
              frame(True, True, 135, body=bytes(16))]
    with Path(path).open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(frames):
            output.write(struct.pack('<IIII', 1700000000 + index, 0, len(packet), len(packet)))
            output.write(packet)


if __name__ == '__main__':
    write(Path(__file__).with_name('icmp_conversations.pcap'))
