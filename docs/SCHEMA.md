# SQLite schema

Schema version: **1**, stored in `PRAGMA user_version`.

The storage module creates the schema only when version is zero and the
existing database has no application objects. Other versions are rejected;
there are no migrations yet. Opening a versioned database also prepares the
conversation statements, which fails if the required table or columns are
missing.

File databases use WAL, `synchronous=FULL`, and a one-second busy timeout.
`:memory:` databases retain SQLite's memory journal mode. Each store owns one
connection and two prepared statements and is used from the capture thread.
No database server is required. SQLite 3.24.0 or newer is required for upserts.

## `conversations`

One row represents a remote endpoint aggregate, not an individual TCP
connection. The table uses `WITHOUT ROWID` and this composite primary key:

```text
(us_ip, remote_ip, remote_port, protocol)
```

| Column | Storage | Meaning |
|---|---|---|
| `us_ip` | INTEGER | Local IPv4, host-order numeric value, 0–4294967295 |
| `remote_ip` | INTEGER | Remote IPv4, same representation |
| `remote_port` | INTEGER | Remote endpoint's port, 0–65535 |
| `protocol` | INTEGER | TCP = 6, UDP = 17 |
| `packets_out` | INTEGER | Cumulative outgoing packet count |
| `packets_in` | INTEGER | Cumulative incoming packet count |
| `bytes_out` | INTEGER | Cumulative outgoing transport payload bytes |
| `bytes_in` | INTEGER | Cumulative incoming transport payload bytes |
| `first_seen` | INTEGER | Earliest observation, Unix seconds |
| `last_seen` | INTEGER | Latest observation, Unix seconds |
| `remote_name` | TEXT or NULL | Optional name, 1–253 characters |

For example, `192.0.2.10` is stored as the integer `3221225994` (`0xC000020A`).
The local ephemeral port is excluded from identity. The same remote address
and port over TCP and UDP produce different rows.

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
Flush scheduling, eviction handoff to storage, shutdown flush, and capture
wiring are not implemented in this module's commit. The application still
holds its current traffic totals only in memory.
