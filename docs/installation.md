# Installation

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

That's it. Wisp will fetch your follow list, sync notes from popular relays, and serve them
at `ws://localhost:7777`. Add this relay URL to your Nostr client.

For more options, see [Configuration](./configuration.md).

## Import / Export

Wisp reads and writes events as JSONL, so backups and migrations are a single command:

```sh
./zig-out/bin/wisp export > backup.jsonl
./zig-out/bin/wisp import < backup.jsonl
```
