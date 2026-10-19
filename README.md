# pigeon

A network watcher daemon written in C. Work in progress.


Build and run the tests with CMake, a C compiler, libpcap headers,
and SQLite development headers, version 3.24.0 or newer:

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Replay a fixture with packet details:

```sh
./build/pigeon --verbose -r tests/fixtures/short_frames.pcap
```

Live capture is currently Linux only and requires capture privileges.
Run `./build/pigeon --verbose` to select the capture interface from the IPv4
route to `1.1.1.1`, falling back to an IPv6 route when IPv4 is unavailable.
Route lookup sends no traffic. `./build/pigeon --verbose <interface>` selects
an interface explicitly. Startup lists all its assigned IPv4 and IPv6
addresses, including IPv6 temporary and link-local addresses.

Address discovery happens once at startup; address and route changes are not
tracked. Capture remains on one interface. Offline replay skips discovery.
Other platforms report ENOSYS for discovery.

Omit `--verbose` to disable packet output; startup,
errors and the final packet count still go to stderr.

Ethernet, IPv4, IPv6, TCP and UDP parsing is separate from printing. Unsupported
protocols and later IP fragments retain only their decoded enclosing headers.
Malformed or truncated supported headers are reported in verbose mode.

Flow tracking is connected to live capture and SQLite. Each parsed TCP/UDP
packet updates its remote conversation using capture timestamps. Live capture
writes to `pigeon.db` in the current directory; select a different path with
`--db <path>`.

Pending deltas flush in one transaction at most once per second during periodic
maintenance. UDP conversations expire after 30 idle seconds and TCP after 120.
Capacity eviction writes the oldest conversation before freeing it. Shutdown
forces a final flush, including on SIGINT and SIGTERM. Forced shutdown and
capacity flushes bypass the periodic throttle. Successful writes clear only
pending counters; failed writes retain them and stop capture with an error.

The table has 4,096 buckets and a capacity of 10,000 conversations. Live
maintenance also runs while capture is idle. Verbose mode prints stored totals
for conversations still active at shutdown; expired or evicted conversations
remain in the database. There is no durable queue for deltas that could not be
written before the process exits.

To track conversations during replay, supply the local address from the file:

```sh
./build/pigeon --verbose --local-ip 192.0.2.10 -r tests/fixtures/short_frames.pcap
```

Replay tracking uses an in-memory database by default. To keep its totals:

```sh
./build/pigeon --local-ip 192.0.2.10 --db replay.db -r tests/fixtures/short_frames.pcap
```

Replaying the same file into the same database adds its traffic again. Without
`--local-ip`, replay performs packet inspection only; `--db` requires replay
tracking. The local-IP option is only accepted with `-r`; live capture uses the
discovered address. Replay maintenance follows packet timestamps, without
waiting for wall-clock time.

The build requires `libsqlite3-dev` and `libpcap-dev` on Debian/Ubuntu.
See [docs/SCHEMA.md](docs/SCHEMA.md) for the schema and write semantics.

DNS response decoding is implemented independently in `src/dns/dns_parse.[ch]`.
It extracts IN-class A and AAAA records, follows CNAME chains, and decodes compressed
names. Results own their lowercase names and retain the minimum chain TTL.
Complete records remain available when a later answer is truncated. The parser
bounds questions, answer records, name walks, and caller-provided output.
It supports printable ASCII labels; binary labels requiring escaped display
are not supported. Authority and additional sections are ignored.
Incoming UDP/53 replies addressed to the local IP now update a bounded DNS cache
and SQLite. Saved mappings reload at startup and expire according to the minimum
CNAME/A TTL. Flows look up names on observation and at flush; a late reply can
name an already flushed conversation without adding its counters again.
Verbose conversation summaries include `name=...` (`name=-` when unknown).
Existing schema-version-1/2 databases migrate transactionally to version 3.

The cache keeps the last observed name for a shared IP; stored conversations
retain their first assigned name. Plaintext UDP/53 A and AAAA responses are learned over IPv4 or IPv6;
TCP DNS, DoH and DoT remain outside this version.

Synthetic query/reply fixtures use RFC 5737 addresses and valid checksums.
Regenerate them with:

```sh
python3 tests/fixtures/make_dns_a_record.py
python3 tests/fixtures/make_dns_compressed.py
python3 tests/fixtures/make_dns_named_flow.py
```

Parser tests replay both fixtures. See [tests/fuzz/README.md](tests/fuzz/README.md)
for deterministic and coverage-guided fuzzing commands.

To inspect DNS naming through the entire pipeline:

```sh
./build/pigeon --verbose --local-ip 192.0.2.10 -r tests/fixtures/flow_before_dns.pcap
```

The service conversation to `198.51.100.42:443` receives `www.example.test`,
even though the traffic precedes the DNS reply. Use `--db <path>` to persist
both conversation totals and DNS mappings from replay.

IPv6 TCP/UDP conversations use the same aggregation, LRU, expiry and persistence
pipeline as IPv4. Address family is part of identity: IPv4-mapped IPv6 addresses
are not collapsed into IPv4. Numeric IPv6 endpoints use brackets before ports.
Common hop-by-hop, routing, destination, fragment and AH extension headers are
decoded with a 16-header limit. Later fragments are not reassembled; ESP and
unknown protocols are displayed at the IP layer but do not create conversations.
IPv6 jumbograms and link-local zone identifiers in storage are not supported.

Replay supports repeated `--local-ip` options for both address families:

```sh
./build/pigeon --verbose --local-ip 2001:db8::10 -r tests/fixtures/ipv6_conversations.pcap
```

This fixture includes AAAA naming, extension headers, TCP/UDP traffic in both
directions, and a truncated TCP payload. Regenerate it with
`python3 tests/fixtures/make_ipv6.py`.
