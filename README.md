# pigeon

A network watcher daemon written in C. Work in progress.


Build and run the tests with CMake, a C compiler, libpcap headers,
SQLite development headers (version 3.24.0 or newer), and wide-character ncurses development headers:

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
The routed interface is preferred when it is up/running, has an IP address,
and provides a supported Ethernet capture format and a selectable descriptor.
Otherwise, Pigeon tries other active, non-loopback IP interfaces in libpcap
order and reports the fallback. This can select a physical interface instead
of an unsupported VPN interface; it does not expose decrypted tunnel traffic.
Capture privileges are needed to probe the format. No interface is selected
if none qualifies. Route lookup sends no traffic. `./build/pigeon --verbose <interface>` selects
an interface explicitly, without automatic fallback. Startup lists all its assigned IPv4 and IPv6
addresses, including IPv6 temporary and link-local addresses.

Address discovery happens once at startup; address and route changes are not
tracked automatically. Capture remains on one interface at a time; the viewers
can request a source change. Offline replay skips discovery.
Other platforms report ENOSYS for discovery.

Omit `--verbose` to disable packet output; startup,
errors and the final packet count still go to stderr.

Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 and ESP parsing is separate from printing. Unsupported
protocols and later IP fragments retain only their decoded enclosing headers.
Malformed or truncated supported headers are reported in verbose mode.

Flow tracking is connected to live capture and SQLite. Each supported
packet updates its remote conversation using capture timestamps. Live capture
writes to `pigeon.db` in the current directory; select a different path with
`--db <path>`.

Pending deltas flush in one transaction at most once per second during periodic
maintenance. UDP and ICMP conversations expire after 30 idle seconds and TCP after 120.
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

The build requires `libsqlite3-dev`, `libpcap-dev`, and `libncurses-dev` on Debian/Ubuntu.
See [docs/SCHEMA.md](docs/SCHEMA.md) for the schema and write semantics.

### Application attribution

Live capture groups conversations by local IP, remote IP, remote port, protocol,
and application. Separate connections and processes running the same executable
combine under its basename, for example `firefox`. Different applications
contacting the same endpoint have separate counters. No PID, process lifetime,
executable path, socket inode, or local port is stored in SQLite.

On Linux, a background worker queries TCP/UDP socket diagnostics over Netlink
and maps socket inodes through `/proc/<pid>/fd` to `/proc/<pid>/exe`. It refreshes
about once per second; packet handling uses a cached lookup and never scans
processes. Exact connections take precedence over unconnected UDP bindings.
IPv4, IPv6, and connected IPv4-mapped IPv6 sockets are supported. Sampling is
bounded to 131,072 sockets and 262,144 file descriptors; incomplete/failed
samples are discarded, and samples older than three seconds are not used.
Confirmed ownership is cached in memory for up to five seconds across transient
owner-scan misses, only while the same kernel socket cookie, inode, address
family, protocol, addresses and ports remain present. Cache hits do not extend
that deadline. Conflicting/ambiguous ownership, a changed socket identity, or a
missing socket prevents reuse; newly confirmed ownership takes precedence.
A failed background sample may use the last successful snapshot only until its
original three-second freshness deadline. This reduces future attribution
splits without reassigning historical unresolved records, changing conversation
keys, or adding process details to SQLite. First packets and sockets whose
owners are never observed can still be unresolved.

Initially unresolved live TCP/UDP accounting is held in memory for up to three
seconds, keyed by both IP addresses, both ports, and transport protocol. The
collector retries the cached ownership lookup on maintenance ticks and when a
later packet has a known owner. If it resolves in time, the held counters enter
that application's conversation; otherwise they enter the unresolved group.
Additional packets do not extend the original deadline. The queue holds at most
1,024 socket tuples; capacity pressure commits the oldest early. It retains only
counters, timestamps, DNS names, and bounded QUIC evidence, never packet payloads.
Explicit flushes, shutdown, and interface switches drain the queue immediately.
This can delay new rows/rate updates by a few seconds. It is best-effort tuple
correlation, not a kernel event history: extremely short-lived or rapidly reused
sockets can still defeat attribution. No existing SQLite rows are reassigned,
and offline replay and captures without an ownership resolver remain immediate.

An empty stored application is displayed as `unresolved`. This includes old
records, offline replays, inaccessible owners, missed short-lived sockets, and
conflicting application owners. Existing unresolved counters are never moved
into a subsequently identified application. Attribution is best effort: sockets
can close, change owners, or reuse a connection tuple between observations.
A shared socket or matching UDP bindings resolve only when the observed owners
agree on the executable name. Process visibility depends on `/proc` permissions;
capture capabilities alone do not necessarily grant that visibility.

Attribution covers the collector's current network namespace; it does not walk
container namespaces. Executable basenames are labels, so unrelated binaries
with the same basename combine. Interpreted programs may appear as `python3`,
and a browser's subprocesses use their executable names. No attempt is made to
infer the originating application behind a proxy, VPN, or local resolver.

### Attribution diagnostics

Stop the current collector, then run:

```sh
sudo ./build/pigeon --debug-attribution 2> /tmp/pigeon-attribution.log
```

This live-only flag writes socket-level diagnostic samples to stderr without
requiring verbose packet dumps. Each line includes local and remote addresses
and ports, the IP protocol number, application, lookup result, snapshot age,
and the last sampler error number (`sample_errno=0` means the last sample
succeeded). It logs lookups, including retries, rather than packet/byte counts.

Results are `snapshot` (fresh ownership scan), `cache` (retained ownership),
`no-snapshot` (sampler has not published a successful result), `stale-snapshot`,
`no-matching-socket`, `owner-missing` (matching socket but no usable executable
owner), `ambiguous-owners`, `owner-cache-expired`, or `clock-error`. A missing
socket or owner does not by itself prove a permission problem; it may have
closed between observations. Repeated tuple/result combinations are suppressed
for five seconds; output is limited to 20 detail lines per second, with a
`rate-limited` summary when further messages were suppressed. This is diagnostic
sampling, not a complete event audit. No process details are added to SQLite.

### Terminal viewer

Run capture and the viewer in separate terminals, using the same database path:

```sh
sudo ./build/pigeon --db /tmp/pigeon.db
```

```sh
./build/pigeon-tui --db /tmp/pigeon.db
```

The viewer needs read access to the database and its SQLite sidecar files. It
opens an existing schema-version-4, -5, -6 or -7 database read-only, never creates or migrates
it, and does not require capture privileges. Quitting the viewer leaves capture
running. `--once` prints a snapshot without requiring an interactive terminal.

Cyan `↓` marks incoming/download traffic; green `↑` marks outgoing/upload
traffic in the overview and column headers. Conversation rows also have an
`IO` column: `↓` for received packets, `↑` for sent packets, and both when both
directions have been observed. These indicators use cumulative packet counts,
including zero-payload packets; they do not indicate which side initiated a
connection or whether traffic is flowing in this refresh interval. Non-Unicode
locales use `v` / `^` instead. LAN detection is not implemented.

The screen contains Traffic overview, Live traffic, Top Conversations,
Applications, and New endpoints. Wide terminals show all panels; smaller
terminals show the overview and one selectable list. The minimum size is
60 columns by 16 rows; all panels
fit at 110 columns by 26 rows. Lists show at most 200 matches.

| Key | Action |
| --- | --- |
| Tab / Shift-Tab | Change panel |
| Up/Down, j/k, PgUp/PgDn, Home/End | Select a row |
| Left/Right | Scroll conversation columns horizontally |
| Enter | Show details; on Applications, filter conversations by selected application |
| d | Show details for the selected entry; Enter/Esc closes |
| a | Clear the exact application filter |
| / | Search recorded name, remote IP, or application; Enter applies |
| Esc | Clear applied search and exact application filter |
| s | Sort Top Conversations and Applications by total, download, or upload |
| l | Sort Live traffic by recency, combined rate, download rate, or upload rate |
| r | Cycle Live traffic window: 30s, 120s, all recorded, 10s |
| f / v | Cycle protocol / address-family filters |
| b | Hold/resume focused list order (navigation holds automatically) |
| p | Pause automatic refresh |
| ? | Show help |
| q / Ctrl-C | Quit viewer |

Navigating a list automatically holds its membership and row order so live
updates cannot move the selection bar. Matching rows continue receiving updated
counters, and the other panels keep refreshing. Rows that leave the current live
sample remain available for inspection with unavailable (`--`) rates. The header
shows **BROWSING: order held**. Press `b`, switch panels, or change filters/sorting
to resume normal list membership and ranking. Opening details also holds the list.

Applications ranks cumulative payload totals per executable basename, with a
separate unresolved group. Use Tab to focus it, select a row, and press Enter to
show that application's conversations. This switches focus to Top Conversations
and clears text search, retaining protocol/family filters. The header shows the
exact application filter; `a` clears it. Unresolved can be selected independently
of all applications. Application details include conversation and remote-IP
counts and the latest observation time. Wide layouts place Applications and New
endpoints side by side below the conversation lists.

Live traffic shows estimated download/upload rates per conversation in `Down/s`
and `Up/s`, ordered by last activity by default. Press `l` to cycle recency,
combined rate, download rate, and upload rate independently of the cumulative
rankings controlled by `s`. Rate sorting is descending among the 200 most recent
conversations matching the current filters/window. Measured rates (including
zero) precede waiting rows; ties retain recency and deterministic key order.
The panel title shows the active sort, and selection follows the conversation
when rankings change. Rate values include `/s`, for example `0 B/s` or
`2.0 KiB/s`. Live traffic and Top Conversations use separate Application,
Domain, IP, Port, and Protocol columns. IP addresses retain their full text;
long domain and application names are abbreviated with `...`. Left/Right
scrolls overflowing columns independently in each conversation panel, with
selection and direction indicators pinned. Narrow panels omit Seen; details
retain it. Protocols without ports show `-` in the Port column, and classified
UDP conversations show `QUIC (UDP)` under Protocol.
New endpoints retains its combined domain/IP labels. Details wrap full domain
names across lines. `--` means that a row is waiting for a second sample at
least one second later.
Only continuously visible rows retain rate baselines: rows that leave and return
because of filtering, recency, or the 200-row limit start sampling again. Counter
resets also restart sampling. Rapid refreshes retain the previous estimate;
pauses or read failures lengthen the interval used by the next successful sample.
Row details show both cumulative totals and the rate estimates.

Refreshes occur once per second. Overview totals and Top Conversations are
cumulative database counters. A `--once` snapshot also prints conversation
counters as totals, since a single read cannot estimate rates. Rates estimate
changes in those counters between
viewer samples. Separate download and upload traces hold up to 60 viewer samples
(fewer in narrow terminals), with the newest at the right. Both use the displayed
shared scale from zero to the visible peak; `_` marks zero traffic. Each trace
shows the elapsed time covered by its visible samples, including refresh delays
or pauses. These count transport
payload, including retransmissions. They are not interface speeds or stored
traffic history. Replay files with old timestamps appear in Top Conversations;
select the all-recorded Live window to see them there too.

Overview and Applications are unfiltered. Application rankings include all
stored conversations before limiting displayed applications to 200. The exact
application filter applies only to Live traffic and Top Conversations. Name/IP
search and address-family filters apply to conversation and endpoint lists;
application search also matches the conversation lists.
Protocol filtering applies to conversations only. New endpoints groups by
remote IP across ports and local addresses, ordered by earliest recorded
first-seen time. When an IP has multiple recorded names, it shows a deterministic
representative name. DNS associations do not establish service ownership.

The database has no collector heartbeat, so packet age cannot distinguish an
idle collector from a stopped one. Read failures leave the previous snapshot
visible with an error while the viewer retries.

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
Existing schema-version-1/2/3/4/5/6 databases migrate transactionally to version 7.

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
decoded with a 16-header limit. Later fragments are not reassembled;
unknown protocols are displayed at the IP layer but do not create conversations.
IPv6 jumbograms and link-local zone identifiers in storage are not supported.

Replay supports repeated `--local-ip` options for both address families:

```sh
./build/pigeon --verbose --local-ip 2001:db8::10 -r tests/fixtures/ipv6_conversations.pcap
```

This fixture includes AAAA naming, extension headers, TCP/UDP traffic in both
directions, and a truncated TCP payload. Regenerate it with
`python3 tests/fixtures/make_ipv6.py`.

## ICMP peer observations

ICMP (IPv4 protocol 1) and ICMPv6 (IPv6 protocol 58) now record remote peers,
including echo requests/replies and router-generated error messages. An ICMP
exchange is an observation, not an established connection. Error messages are
counted against the outer sender, not the destination embedded in a quoted
packet. They are not attributed to TCP/UDP applications.

ICMP has no ports. Rows use `remote_port=0` as a storage sentinel and an empty
application, grouping all message types for a local/remote pair and protocol.
The TUI/GUI display the protocol and omit the port. The `f` protocol filter in
the TUI cycles through any, TCP, UDP, ICMP, ICMPv6 and ESP.

ICMPv6 neighbor/router discovery (types 133–137), multicast listener control
(types 130–132 and 143), and IPv4 router discovery (types 9/10) remain excluded
as local-link control traffic. This is not a general LAN-address filter: ping
traffic to another LAN device is still an observation. Packets between two
known addresses of this device remain ignored. Later fragments are not
reassembled; checksums are not verified, as with existing protocol parsers.

Payload byte counts exclude Ethernet/IP and the decoded ICMP header: eight
bytes for IPv4 and IPv6 echo/errors, four for other ICMPv6 message types. Error
payloads include the quoted packet; these totals represent control traffic,
not application data. Type/code appear in verbose dumps, not in persisted keys.

The collector migrates older schemas to v7 transactionally on its next start,
preserving existing observations and DNS data. Both updated viewers accept v4,
v5, v6 and v7; older GUI binaries need rebuilding before reading the new schema.

Replay both families without capture privileges:

```sh
./build/pigeon --verbose --local-ip 192.0.2.10 --local-ip 2001:db8::10 \
  -r tests/fixtures/icmp_conversations.pcap
```

Regenerate the fixture with `python3 tests/fixtures/make_icmp.py`.

## QUIC classification

UDP aggregates can display `QUIC (UDP)` when sufficient handshake-header evidence
has been observed. Transport protocol remains 17, and the conversation key and
payload counters do not change. The UDP filter includes classified QUIC traffic.
The schema-v6 `quic` flag is persisted with a sticky upsert: later unclassified
packets or a collector restart cannot remove a previously observed classification.
Old observations migrate with `quic=0`; UDP port 443 does not imply QUIC.

The detector validates the first long-header packet for QUIC v1 or v2, including
CID bounds, token/packet lengths and sufficient protected bytes. It seeds a
candidate only from a fully captured Initial datagram of at least 1200 bytes
with a source CID of at least eight bytes. A valid Initial/Handshake in the
opposite direction, on the same local UDP port, must use that source CID as its
destination CID within 30 seconds. A bounded candidate is held per aggregate;
interleaved handshakes may conservatively go unidentified.

Short-only captures, zero/short source IDs, unknown versions, unsupported packet
types and insufficient evidence remain UDP. This is header-based inference,
not cryptographic validation or payload decryption. It does not imply HTTP/3.
The label means QUIC was observed somewhere in the aggregate; its lifetime byte
totals can also include other UDP traffic sharing the same aggregate identity.

Implementation references: [QUIC v1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2),
[QUIC v2](https://www.rfc-editor.org/rfc/rfc9369.html#section-3.2), and
[header protection](https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.2).

```sh
./build/pigeon --verbose --local-ip 192.0.2.10 --local-ip 2001:db8::10 \
  -r tests/fixtures/quic_conversations.pcap
```

The fixture deliberately contains synthetic header evidence with opaque test
bodies, not a cryptographically valid QUIC exchange. Regenerate it with
`python3 tests/fixtures/make_quic.py`.

## VLAN and ESP peers

The Ethernet decoder unwraps up to four standard 802.1Q (0x8100) and 802.1ad
(0x88a8) tags, including stacked/Q-in-Q frames. It retains the TPID and TCI for
verbose output and passes the inner EtherType/payload to the existing IP
parsers. Truncated tags and excessive nesting are rejected safely. VLAN headers
and Ethernet padding do not contribute to protocol payload counters. Tags are
not persisted or added to the conversation key; identical endpoints observed
across tags aggregate together. Only tags present in the capture can be shown.

Native ESP (IP protocol 50) is tracked over IPv4 and IPv6 using the visible
outer peer addresses. The decoder reads the SPI and sequence number but never
decrypts or authenticates the packet. SPIs are shown in verbose output, not
persisted as identities: opposing security associations and rekeys combine
into one peer observation. Rows have protocol=50, remote_port=0 and an empty
application; neither inner destinations nor application ownership are guessed.

Standard ESP-in-UDP NAT traversal is also recognized on UDP port 4500 using the
RFC 3948 nonzero-SPI demultiplexing rule and a complete visible ESP header.
This assumes standard IPsec use of that reserved port; it is not cryptographic
validation. IKE packets with the four-zero-byte Non-ESP marker and one-byte
0xff NAT keepalives remain UDP. An incomplete/invalid ESP envelope on UDP is
left as UDP. Recognized encapsulated ESP joins the same protocol-50 peer
aggregate as native ESP and is counted once, not also as UDP. The underlying
outer IP protocol and UDP ports remain available in verbose packet output.

ESP byte counters measure the opaque body after the eight-byte SPI/sequence
header, excluding outer Ethernet, VLAN, IP and any UDP header. They include
cipher/IV, padding/trailer and authentication overhead where present; these
are not decrypted application bytes. A complete captured header can count
body bytes declared on the wire even if the body capture is truncated. ESP
entries expire after 30 idle seconds, with observations retained in SQLite.
Later fragments still require reassembly and are not tracked individually.

Schema v7 widens the accepted protocol set for ESP. Existing counters, names,
DNS data and QUIC classification survive its transactional migration. Both
updated viewers accept schemas v4–v7 and offer an ESP filter with no port.
Restart the collector and viewers after deploying this change.

```sh
./build/pigeon --verbose --local-ip 192.0.2.10 --local-ip 2001:db8::10 \
  -r tests/fixtures/vlan_esp_conversations.pcap
```

Regenerate the synthetic fixture with `python3 tests/fixtures/make_vlan_esp.py`.
Protocol references: [ESP](https://www.rfc-editor.org/rfc/rfc4303.html#section-2)
and [ESP-in-UDP](https://www.rfc-editor.org/rfc/rfc3948.html#section-2).

Capture interface selection from viewers
----------------------------------------

Start the collector normally, then press **i** in `pigeon-tui`, or use the
GUI's **Interfaces** button. The selector shows the current source and each
interface's active/support status. Choose **Automatic** or an active supported
interface. Automatic selects once, rather than following future route changes.
The collector opens the new capture and prepares its local addresses before
flushing pending counters and switching. Failed preparation keeps the current
source; recorded SQLite history is preserved. A brief capture gap is possible
while switching. These controls do not add new capture formats or concurrent
multi-interface capture.

Control is local to the Linux machine through `<canonical database path>.control`.
The database remains read-only in both viewers. Root and the user who launched
the collector are authorized (`SUDO_UID` for `sudo ./build/pigeon`). A collector
started directly as root accepts only root. Restart the collector after upgrading
to enable control. Old collectors and copied databases still work for viewing;
the selector reports control unavailable. The database path plus `.control`
must fit the 107-byte Unix socket pathname limit. The socket is removed on normal
shutdown; an owned stale socket is recovered after a crash. A second collector
using the same control socket is rejected. No control socket is used for offline
replay.
