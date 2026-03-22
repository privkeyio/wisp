# wisp - a lightweight nostr relay

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A fast, lightweight [nostr](https://github.com/nostr-protocol/nostr) relay written in Zig.

## Why Wisp?

- **Fast**: 2x higher throughput than strfry, 10x lower latency
- **Small**: Single 1.2MB binary, ~15MB RAM at idle
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
# 1. Install dependencies (requires Zig 0.15+)
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

* NIPs: 1, 2, 9, 11, 13, 16, 22, 33, 40, 42, 45, 50, 65, 70, 77, 86
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

## Deploy (wss://)

To make your relay publicly accessible with TLS, put Caddy in front of wisp:

```sh
# Install Caddy
sudo apt install -y caddy
```

Create `/etc/caddy/Caddyfile`:

```
relay.yourdomain.com {
    reverse_proxy localhost:7777
}
```

Create `/etc/systemd/system/wisp.service`:

```ini
[Unit]
Description=Wisp Nostr Relay
After=network.target

[Service]
ExecStart=/usr/local/bin/wisp --spider-admin npub1yourkey...
WorkingDirectory=/var/lib/wisp
Restart=always
User=wisp

[Install]
WantedBy=multi-user.target
```

```sh
# Set up and start
sudo useradd -r -s /bin/false wisp
sudo mkdir -p /var/lib/wisp
sudo chown wisp:wisp /var/lib/wisp
sudo cp zig-out/bin/wisp /usr/local/bin/
sudo systemctl enable --now wisp caddy
```

Add `trust_proxy = true` to your `wisp.toml` if using rate limiting behind Caddy.

Your relay is now live at `wss://relay.yourdomain.com`.

## Benchmarks

| Relay | Events/sec | p50 Latency | p99 Latency |
|-------|-----------|-------------|-------------|
| Wisp | 1,993 | 0.55ms | 0.82ms |
| strfry | 872 | 4.28ms | 9.92ms |

*4 concurrent workers, 1k events. [Full results](https://github.com/privkeyio/nostr-bench/blob/main/reports/BENCHMARK_RESULTS.md)*

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues and submitting pull requests.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a history of changes to this project.

## License

MIT
