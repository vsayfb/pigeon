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
Run `./build/pigeon --verbose` to select the interface, local IPv4 address
and gateway from the kernel route to `1.1.1.1`. This lookup sends no traffic.
Use `./build/pigeon --verbose <interface>` to constrain that route lookup to
a named interface. Discovery fails if that interface has no usable route.
Startup reports the selected address and gateway (zero for a direct route).

Discovery happens once at startup; address and route changes are not tracked.
Offline replay skips discovery. Other platforms report ENOSYS for discovery.

Omit `--verbose` to disable packet output; startup,
errors and the final packet count still go to stderr.

Ethernet, IPv4, TCP and UDP parsing is separate from printing. Unsupported
protocols and later IP fragments retain only their decoded enclosing headers.
Malformed or truncated supported headers are reported in verbose mode.

Flow tracking is connected to live capture. Each parsed TCP/UDP packet updates
its remote conversation using capture timestamps. Verbose mode prints pending
conversation totals on shutdown; totals are currently held only in memory.
The table has 4,096 buckets and a capacity of 10,000 conversations. Until a
storage handler is connected, reaching capacity with a new conversation stops
capture and returns an error instead of evicting unconsumed counters.

To track conversations during replay, supply the local address from the file:

```sh
./build/pigeon --verbose --local-ip 192.0.2.10 -r tests/fixtures/short_frames.pcap
```

Without `--local-ip`, offline replay retains packet inspection only.
The option is only accepted with `-r`; live capture uses the discovered address.

The SQLite storage module is implemented and tested independently; it is not
connected to capture yet. It adds batched conversation deltas transactionally
and preserves totals across database reopen. See [docs/SCHEMA.md](docs/SCHEMA.md)
for the schema and write semantics. On Debian/Ubuntu its build dependency is
`libsqlite3-dev` alongside `libpcap-dev`.
