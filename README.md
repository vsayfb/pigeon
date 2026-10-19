# pigeon

A network watcher daemon written in C. Work in progress.


Build and run the tests (requires CMake, a C compiler and libpcap headers):

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
