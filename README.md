# wisp - a lightweight nostr relay

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A fast, lightweight [nostr](https://github.com/nostr-protocol/nostr) relay written in Zig.

## Why Wisp?

- **Fast**: ~9x higher throughput than strfry, sub-millisecond p99 latency
- **Small**: Single binary, ~11MB RAM at idle
- **Simple**: One command to run your personal relay with your feed
- **Spider Mode**: Automatically syncs events from people you follow

## Quickstart

### Docker

```sh
docker run -d -p 7777:7777 -v wisp-data:/data ghcr.io/privkeyio/wisp --spider-admin npub1yourkey...
```

### Build from source

Download the [latest release](https://github.com/privkeyio/wisp/releases) or build from source:

```sh
# 1. Install dependencies (requires Zig 0.16.0)
sudo apt install -y liblmdb-dev libsecp256k1-dev libssl-dev

# 2. Build
git clone https://github.com/privkeyio/wisp && cd wisp
zig build -Doptimize=ReleaseFast

# 3. Run (replace with your npub)
./zig-out/bin/wisp --spider-admin npub1yourkey...
```

That's it. Wisp will fetch your follow list, sync notes from popular relays, and serve them at `ws://localhost:7777`. Add this relay URL to your Nostr client.

For more options, see `wisp.toml.example`.

## Features

* NIPs: 1, 2, 9, 11, 13, 16, 33, 40, 42, 45, 50, 65, 70, 77, 86
* LMDB storage (no external database)
* Spider mode for syncing events from external relays
* Import/export to JSONL
* Prometheus metrics at `GET /metrics`

## Monitoring

Operational metrics are exposed in Prometheus format at `GET /metrics` on the
relay's port (connections, events stored/rejected/broadcast, REQ count, rate
limiting). The endpoint honors the relay's IP allowlist/blocklist, so restrict
it there or at your reverse proxy/firewall if you don't want it public.

## Import/Export

```sh
./zig-out/bin/wisp export > backup.jsonl
./zig-out/bin/wisp import < backup.jsonl
```

## Configuration

Copy `wisp.toml.example` to `wisp.toml` and customize, or use environment variables with the `WISP_` prefix:

```sh
WISP_PORT=8080 ./zig-out/bin/wisp
```

Environment variables override the config file. See the **[Configuration reference](docs/configuration.md)** for every setting, its environment variable, default, and meaning.

## Deploy (wss://)

To make your relay publicly accessible with TLS, run wisp with Caddy:

```sh
# Run wisp
docker run -d --restart always -p 7777:7777 -v wisp-data:/data \
  ghcr.io/privkeyio/wisp --spider-admin npub1yourkey...

# Install Caddy for automatic TLS
sudo apt install -y caddy
```

Create `/etc/caddy/Caddyfile`:

```
relay.yourdomain.com {
    reverse_proxy localhost:7777
}
```

```sh
sudo systemctl restart caddy
```

Your relay is now live at `wss://relay.yourdomain.com`.

## Benchmarks

Peak write throughput, all relays at 100% delivery:

| Relay | Events/sec | p99 Latency | Memory (RSS) |
|-------|-----------:|------------:|-------------:|
| **Wisp** | **25,600** | **0.28 ms** | 11 MB |
| nostr-rs-relay | 5,400 | 5.9 ms | 20 MB |
| strfry | 2,800 | 2.9 ms | 3 MB |

*[nostr-bench](https://github.com/privkeyio/nostr-bench), 5,000 events x 4 workers at peak rate (`--rate 0`), native release builds on a 16-core Linux host, with the event-rate limit raised. `RssAnon` sampled during the run. These are peak figures with Wisp in `sync = none` (non-durable); Wisp's default is `sync = meta` (durable, never corrupts), which trades raw throughput for crash safety. strfry and nostr-rs-relay write durably by default, so a fair durable comparison runs Wisp in `meta`/`full` (see [benchmarks](docs/benchmarks.md)). Wisp leads on throughput (~9x strfry, ~5x nostr-rs-relay) and p99 latency; strfry stays smallest in memory.*

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues and submitting pull requests.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a history of changes to this project.

## License

MIT
