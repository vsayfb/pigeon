# SQLite schema

Schema version: **7**, stored in `PRAGMA user_version`.

The storage module creates the schema only when version is zero and the
existing database has no application objects. Versions 1, 2, 3, 4, 5 and 6 migrate
transactionally: version 1 first gains the DNS table, then integer IPv4 keys
are converted to 4-byte network-order blobs. Version 3 also accepts 16-byte
IPv6 keys. Version 4 adds application to the conversation key; existing rows
receive an empty application because historical ownership is unavailable.
Version 5 adds ICMP (1) and ICMPv6 (58), retaining the same key and columns.
Version 6 adds a `quic` metadata flag with a default of zero.
Version 7 permits ESP (50) while retaining the same columns and key.
Totals, names, DNS mappings and timestamps are preserved. Other versions are
rejected. A failed migration restores the schema, rows and user version.
Opening a versioned database also prepares the
conversation statements, which fails if the required table or columns are
missing.

File databases use WAL, `synchronous=FULL`, and a one-second busy timeout.
`:memory:` databases retain SQLite's memory journal mode. Each store owns one
connection and four prepared statements and is used from the capture thread.
No database server is required. SQLite 3.24.0 or newer is required for upserts.

## `conversations`

One row represents a remote endpoint aggregate for one application, not an
individual TCP connection. The table uses `WITHOUT ROWID` and this composite primary key:

```text
(us_ip, remote_ip, remote_port, protocol, application)
```

| Column | Storage | Meaning |
|---|---|---|
| `us_ip` | BLOB | Local IP: 4 bytes for IPv4, 16 for IPv6 |
| `remote_ip` | BLOB | Remote IP, same byte length/family as local IP |
| `remote_port` | INTEGER | Remote endpoint's port, 0–65535; ICMP and ESP use a zero sentinel |
| `protocol` | INTEGER | ICMP = 1, TCP = 6, UDP = 17, ESP = 50, ICMPv6 = 58 |
| `quic` | INTEGER NOT NULL | 0/1: QUIC observed within a UDP aggregate; not part of identity |
| `application` | TEXT NOT NULL | Executable basename, at most 255 bytes; empty when unresolved |
| `packets_out` | INTEGER | Cumulative outgoing packet count |
| `packets_in` | INTEGER | Cumulative incoming packet count |
| `bytes_out` | INTEGER | Cumulative outgoing transport payload bytes |
| `bytes_in` | INTEGER | Cumulative incoming transport payload bytes |
| `first_seen` | INTEGER | Earliest observation, Unix seconds |
| `last_seen` | INTEGER | Latest observation, Unix seconds |
| `remote_name` | TEXT or NULL | Optional name, 1–253 characters |

Address blobs use network byte order. For example, `192.0.2.10` is `X'C000020A'`;
`2001:db8::10` is `X'20010DB8000000000000000000000010'`. Blob length identifies
the family. IPv4-mapped IPv6 remains a separate 16-byte identity. `hex(remote_ip)`
is useful when inspecting raw SQLite rows; the executable formats numeric IPs.
The local ephemeral port is excluded from identity. The same remote address
and port over TCP and UDP produce different rows. Different application names
also produce different rows. Connections from multiple processes or restarts
with the same executable basename combine. Local ports and process/socket
metadata are used in memory for attribution and are not persisted. Endpoint-only
totals can be obtained by grouping without `application` and summing counters.
An empty application is a separate grouping for unresolved ownership, including
replay and migrated history; those counters are not reassigned after resolution.

Counters are nonnegative signed 64-bit integers. Payload bytes exclude
Ethernet/IP/transport headers and Ethernet padding; TCP retransmissions are
counted again. SQLite integer overflow would convert a sum to REAL, so CHECK
constraints reject non-integer totals and roll back the batch instead.
`first_seen` must be less than or equal to `last_seen`.

## Batch writes

`store_flush()` accepts an array of copied `store_row` snapshots. For each row,
it inserts the counters or adds them to the existing counters. It retains the
minimum `first_seen`, maximum `last_seen`, and first non-NULL `remote_name`.
Names are bound parameters, not interpolated SQL. An empty C name represents
SQL NULL; the C buffer holds at most 253 bytes plus its NUL terminator.

The entire batch runs inside `BEGIN IMMEDIATE` / `COMMIT`. Any validation,
statement, or commit failure triggers rollback; a failed rollback makes the
store unavailable for further writes until reopened. Errors are available via
`store_error()`. `store_lookup()` copies a row's totals and name without
borrowing statement memory.

A successful flush does not clear its input deltas. The caller must clear them
only after success; submitting the same successful batch again adds it again.
Flow tracking now flushes pending deltas periodically, before capacity eviction,
and on shutdown. Periodic flushes are throttled to one attempt per second;
explicit and capacity flushes bypass this throttle. UDP, ICMP and ESP entries expire after
30 idle seconds and TCP entries after 120, following a successful flush.
Deltas are cleared only after commit. Failed writes preserve pending deltas
and prevent expiry or eviction; the executable stops capture and returns an
error if writing fails. It attempts a final flush before teardown.

Live capture defaults to `pigeon.db`; `--db` selects another path. Replay with
`--local-ip` defaults to an in-memory database unless `--db` is specified.
Verbose shutdown output shows stored totals for entries still active in memory.
Expired and evicted entries remain queryable in SQLite.


## `dns_cache`

| Column | Storage | Meaning |
|---|---|---|
| `ip` | BLOB PRIMARY KEY | IPv4/IPv6 address, 4/16 network-order bytes |
| `name` | TEXT NOT NULL | Last observed name, 1–253 bytes in the C API |
| `observed_at` | INTEGER NOT NULL | Capture timestamp in Unix seconds |
| `expires_at` | INTEGER NOT NULL | Exclusive TTL expiry in Unix seconds |

`dns_cache_expiry` indexes `expires_at`. Each observed mapping is upserted in
an atomic write before updating the memory map. Older capture timestamps
cannot replace newer mappings; equal timestamps allow the latest observation
to win. A zero TTL stores an immediately expired replacement, invalidating the
previous name. Expiry is `observed_at + minimum_chain_ttl`, saturating at
`INT64_MAX`. Expired rows remain on disk but are excluded from live reload and
lookup. DNS reply mappings are saved individually; earlier successful mappings
remain saved if a later mapping in that reply cannot be written.

The memory cache has a capacity of 4,096 IPs and 256 hash buckets. Capacity
replacement prefers an expired entry, then the oldest observation. Startup
loads mappings in observation order, retaining the newest ones when over
capacity. Offline startup loads without a wall-clock cutoff, while lookup uses
the replay timestamp and rejects names observed in the future.

A mapping is usable only while `observed_at <= now < expires_at`. Flows check
at observation and again at flush, including clean entries receiving a late
name. A zero-counter upsert can name a previously flushed conversation without
adding traffic. Once assigned, the conversation's name remains historical and
is preserved even when the cache mapping changes or expires.

A and AAAA records from incoming plaintext UDP/53 responses addressed to an
assigned local IP are learned over either family. TCP DNS, DoH and DoT are not learned. Complete
results from partial responses are accepted; malformed responses are ignored.
This is an observed IP-to-name association, not proof of the service behind an
IP. Shared CDN addresses use the last observed cache name; a stored conversation
retains its first assigned name.

## ICMP conventions (v5)

ICMP rows require IPv4 addresses; ICMPv6 rows require IPv6 addresses. Both require
`remote_port=0` and `application=''`; CHECK constraints enforce these conventions.
Viewers show a dash/omit the port rather than interpreting it as an actual port.
The same peer's echo and error message types aggregate together. Error messages
use the outer sender as the peer; quoted packets do not create additional rows.
No historical application attribution is inferred for ICMP.

Byte counters count the message body after the decoded header (eight bytes for
IPv4 and IPv6 echo/error messages, four for other ICMPv6 messages), bounded by
the declared IP length and excluding Ethernet padding. A capture missing body
bytes can still count their declared length when its header is complete. No
fragment reassembly or checksum validation is performed. Type/code are available
in verbose packet output and are not separate columns or key fields.

## QUIC metadata (v6)

`quic` is restricted to integer 0 or 1, with 1 allowed only when protocol=17.
It does not enter the primary key and does not alter byte/packet counting.
Upserts merge it using `max(existing, incoming)`, preserving observed evidence
across flushes, eviction, expiry and restarts. Historical rows migrate with zero;
there is no inference from ports or persisted old byte totals.

The flag is passive header-based classification, not authentication or proof
that every UDP packet in the aggregate is QUIC. It does not distinguish HTTP/3.
The collector requires matching bidirectional CID evidence; a failed or missing
handshake observation leaves the flag unset. Read-only viewers use zero for
schemas v4/v5 and read the stored flag in v6/v7.

## ESP observations and VLAN handling (v7)

Protocol 50 rows accept either IP family but require remote_port=0,
application='' and quic=0. They aggregate by visible outer local/remote peer,
not by SPI. Native ESP and standard UDP/4500-encapsulated ESP share this identity;
recognized encapsulated packets do not also create UDP counter increments.
IKE (zero Non-ESP marker) and NAT keepalives remain separate UDP traffic.

ESP counters measure bytes after the visible eight-byte ESP header, including
opaque protection overhead. No cipher, inner address/port, plaintext length,
process attribution, authentication result or SPI is persisted. Schema-v6
migration rebuilds the conversation table transactionally to widen its CHECK
constraints, preserving all existing columns, counters and QUIC flags. DNS
storage is unchanged. Readers retain compatibility with earlier supported files.

VLAN tags affect decoding only. Up to four 0x8100/0x88a8 headers can be unwrapped;
tags are shown in verbose output and do not enter stored identities or counters.
