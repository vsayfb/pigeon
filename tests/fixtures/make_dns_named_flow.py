#!/usr/bin/env python3
"""Writes DNS-before-flow and flow-before-DNS synthetic replay fixtures."""

from pathlib import Path
from dns_fixture import write_named_flow

if __name__ == "__main__":
    directory = Path(__file__).parent
    write_named_flow(directory / "dns_before_flow.pcap", True)
    write_named_flow(directory / "flow_before_dns.pcap", False)
