# DNS parser fuzzing

The normal CMake build provides a deterministic mutation/random-input runner:

```sh
./build/fuzz_dns_parse 1000000
```

An optional second argument supplies a raw DNS message as the mutation seed
(not a whole pcap file). Without it, the runner uses an embedded A response.
The runner checks return codes, output bounds, NUL termination, TTL range,
zero-capacity behavior, and unchanged output beyond the returned count.
ASan/UBSan are enabled by the project's default development build.

For coverage-guided fuzzing with Clang/libFuzzer:

```sh
clang -std=c11 -Wall -Wextra -Werror -g \
  -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
  -DDNS_LIBFUZZER -Isrc \
  tests/fuzz/fuzz_dns_parse.c src/dns/dns_parse.c -o /tmp/pigeon-fuzz-dns
mkdir -p /tmp/pigeon-dns-corpus
/tmp/pigeon-fuzz-dns /tmp/pigeon-dns-corpus -max_len=65535
```

Stop libFuzzer with Ctrl+C. It reports crashes and retains interesting inputs
in its corpus. Seed files may contain complete or malformed raw DNS messages.
