#!/usr/bin/env python3
"""Writes a DNS query/reply with compressed owners and CNAME targets."""

from pathlib import Path
import sys

from dns_fixture import write_fixture

if __name__ == "__main__":
    write_fixture(sys.argv[1] if len(sys.argv) > 1 else
                  Path(__file__).with_name("dns_compressed.pcap"), True)
