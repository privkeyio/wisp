# wisp - a lightweight nostr relay

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A fast, lightweight [nostr](https://github.com/nostr-protocol/nostr) relay written in Zig.

## Why Wisp?

- **Fast**: 8x higher throughput than strfry, 15x lower latency
- **Small**: Single 1.2MB binary, ~15MB RAM at idle
- **Simple**: One command to run your personal relay with your feed
- **Spider Mode**: Automatically syncs events from people you follow

## Benchmarks

| Relay | Events/sec | p50 Latency | p99 Latency |
|-------|-----------|-------------|-------------|
| Wisp | 7,983 | 0.39ms | 0.70ms |
| strfry | 1,014 | 5.74ms | 10.70ms |

*8 concurrent workers, 10k events. [Full results](https://github.com/privkeyio/nostr-bench)*

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

* NIPs: 1, 9, 11, 16, 33, 40, 42, 45, 50, 77
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

## License

LGPL-2.1-or-later
