#!/usr/bin/env python3
"""Generate tagged IPv4/IPv6 UDP, native ESP, ESP-in-UDP, IKE and a keepalive."""
from pathlib import Path
import ipaddress
import struct
import sys

sys.dont_write_bytecode = True

from make_icmp import checksum
from make_quic import frame as udp_frame


def tagged(frame, tags):
    headers = b''.join(struct.pack('!HH', tpid, vid) for tpid, vid in tags)
    return frame[:12] + headers + frame[12:]


def esp_body(incoming):
    return struct.pack('!II', 2 if incoming else 1, 7) + b'opaque!!'


def native(ipv6, incoming):
    local = '2001:db8::10' if ipv6 else '192.0.2.10'
    peer = '2001:db8::42' if ipv6 else '198.51.100.42'
    source, destination = (peer, local) if incoming else (local, peer)
    source = ipaddress.ip_address(source).packed
    destination = ipaddress.ip_address(destination).packed
    body = esp_body(incoming)
    if ipv6:
        header = struct.pack('!IHBB', 6 << 28, len(body), 50, 64) + source + destination
    else:
        header = struct.pack('!BBHHHBBH', 0x45, 0, 20 + len(body), 0, 0, 64, 50, 0) + source + destination
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return bytes.fromhex('020000000002020000000001') + struct.pack('!H', 0x86dd if ipv6 else 0x0800) + header + body


def write(path):
    frames = []
    single = [(0x8100, 100)]
    stacked = [(0x88a8, 200), (0x8100, 100)]
    for ipv6, peer in [(False, '198.51.100.99'), (True, '2001:db8::99')]:
        frames.append(tagged(udp_frame(ipv6, False, b'vlan', peer, 443), single))
        frames.append(tagged(udp_frame(ipv6, True, b'vlan', peer, 443), stacked))
    for ipv6 in (False, True):
        frames.append(tagged(native(ipv6, False), stacked))
        frames.append(native(ipv6, True))
    for ipv6, peer in [(False, '198.51.100.42'), (True, '2001:db8::42')]:
        frames.append(tagged(udp_frame(ipv6, False, esp_body(False), peer, 4500), single))
        frames.append(udp_frame(ipv6, True, esp_body(True), peer, 4500))
    frames.append(udp_frame(False, False, bytes(24), '198.51.100.42', 4500))  # IKE marker
    frames.append(udp_frame(False, False, b'\xff', '198.51.100.42', 4500))  # keepalive
    frames.append(tagged(bytes.fromhex('0200000000020200000000010806') + bytes(28), single))
    with Path(path).open('wb') as output:
        output.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(frames):
            output.write(struct.pack('<IIII', 1700000000 + index, 0, len(packet), len(packet)))
            output.write(packet)


if __name__ == '__main__':
    write(Path(__file__).with_name('vlan_esp_conversations.pcap'))
