"""Synthetic DNS fixtures: RFC 5737 IPv4 addresses and fake MAC addresses."""

import socket
import struct


def name(text):
    return b"".join(bytes([len(label)]) + label.encode("ascii")
                    for label in text.split(".")) + b"\0"


def response(compressed):
    question = name("www.example.test") + struct.pack("!HH", 1, 1)
    message = bytearray(struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 3, 0, 0) + question)
    owner = b"\xc0\x0c" if compressed else name("www.example.test")

    for target, ttl in (("edge.example.test", 60), ("origin.example.test", 120)):
        encoded = name(target)

        if compressed:
            label = target.split(".")[0].encode("ascii")
            encoded = bytes([len(label)]) + label + b"\xc0\x10"

        message.extend(owner + struct.pack("!HHIH", 5, 1, ttl, len(encoded)))
        target_offset = len(message)
        message.extend(encoded)
        owner = struct.pack("!H", 0xC000 | target_offset) if compressed else name(target)

    message.extend(owner + struct.pack("!HHIH", 1, 1, 300, 4))
    message.extend(socket.inet_aton("198.51.100.42"))

    return bytes(message)


def checksum(data):
    if len(data) % 2:
        data += b"\0"

    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return ~total & 0xFFFF


def frame(dns, reply, server_address="192.0.2.53", server_port=53):
    client = socket.inet_aton("192.0.2.10")
    server = socket.inet_aton(server_address)
    src, dst = (server, client) if reply else (client, server)
    sport, dport = (server_port, 49152) if reply else (49152, server_port)
    length = 8 + len(dns)
    udp = struct.pack("!HHHH", sport, dport, length, 0) + dns
    pseudo = src + dst + struct.pack("!BBH", 0, 17, length)
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + length, 1, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    client_mac = bytes.fromhex("020000000001")
    server_mac = bytes.fromhex("020000000053")
    src_mac, dst_mac = (server_mac, client_mac) if reply else (client_mac, server_mac)

    return dst_mac + src_mac + b"\x08\x00" + ip + udp


def write_fixture(path, compressed):
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    query += name("www.example.test") + struct.pack("!HH", 1, 1)
    frames = [frame(query, False), frame(response(compressed), True)]

    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        for i, data in enumerate(frames):
            out.write(struct.pack("<IIII", 1700000000 + i, 0, len(data), len(data)))
            out.write(data)


def write_named_flow(path, dns_first):
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    query += name("www.example.test") + struct.pack("!HH", 1, 1)
    reply = frame(response(True), True)
    service = frame(b"x", False, "198.51.100.42", 443)
    frames = [frame(query, False)] + ([reply, service] if dns_first else [service, reply])

    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

        for i, data in enumerate(frames):
            out.write(struct.pack("<IIII", 1700000000 + i, 0, len(data), len(data)))
            out.write(data)
