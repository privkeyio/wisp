# wisp - a lightweight nostr relay

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A fast, lightweight [nostr](https://github.com/nostr-protocol/nostr) relay written in Zig.

## Why Wisp?

- **Fast**: 2x higher throughput than strfry, 10x lower latency
- **Small**: Single 1.2MB binary, ~15MB RAM at idle
- **Simple**: One command to run your personal relay with your feed
- **Spider Mode**: Automatically syncs events from people you follow

## Benchmarks

| Relay | Events/sec | p50 Latency | p99 Latency |
|-------|-----------|-------------|-------------|
| Wisp | 1,993 | 0.55ms | 0.82ms |
| strfry | 872 | 4.28ms | 9.92ms |

*4 concurrent workers, 1k events. [Full results](https://github.com/privkeyio/nostr-bench/blob/main/reports/BENCHMARK_RESULTS.md)*

## Quickstart

Download the [latest release](https://github.com/privkeyio/wisp/releases) or build from source:

```sh
# Build (requires Zig 0.15+)
sudo apt install -y liblmdb-dev libsecp256k1-dev libssl-dev
git clone https://github.com/privkeyio/wisp && cd wisp
zig build -Doptimize=ReleaseFast

# Run your personal relay (replace with your npub)
./zig-out/bin/wisp --spider-admin npub1yourkey...
```

Spider reads your follow list and pulls your feed. Point your client at `ws://localhost:7777`.

## Features

* NIPs: 1, 9, 11, 13, 16, 33, 40, 42, 45, 50, 65, 70, 77
* LMDB storage (no external database)
* Spider mode for syncing events from external relays
* Import/export to JSONL

## Import/Export

```sh
./zig-out/bin/wisp export > backup.jsonl
./zig-out/bin/wisp import < backup.jsonl
```

## Configuration

Copy `wisp.toml.example` to `wisp.toml` and customize, or use environment variables with `WISP_` prefix:

```sh
WISP_PORT=8080 ./zig-out/bin/wisp
```

See `wisp.toml.example` for all options.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues and submitting pull requests.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a history of changes to this project.

## License

LGPL-2.1-or-later
