# wisp - a lightweight nostr relay

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A lightweight [nostr](https://github.com/nostr-protocol/nostr) relay written in Zig.

* Supports NIPs: 1, 9, 11, 16, 33, 40, 42, 45, 50, 77
* LMDB storage (no external database)
* Spider mode for syncing events from external relays
* Single binary, minimal dependencies
* Requires Zig 0.15+

## Build

```sh
# Debian/Ubuntu
sudo apt install -y liblmdb-dev libsecp256k1-dev libssl-dev

git clone https://github.com/privkeyio/wisp
cd wisp && zig build
```

## Run

```sh
./zig-out/bin/wisp
```

Listens on `127.0.0.1:7777`, stores data in `./data`.

## Import/Export

```sh
# Export all events to JSONL
./zig-out/bin/wisp export > backup.jsonl

# Import events from JSONL
./zig-out/bin/wisp import < backup.jsonl

# Use custom database path
./zig-out/bin/wisp export --db /path/to/db > backup.jsonl
```

## Configure

Copy `wisp.toml.example` to `wisp.toml` and customize, or use environment variables:

```sh
cp wisp.toml.example wisp.toml
./zig-out/bin/wisp wisp.toml
```

All config options can be set via `WISP_` prefixed environment variables (e.g., `WISP_PORT=8080`).

## Spider Mode

Spider mode syncs events from external relays for specified pubkeys:

```sh
# Follow specific pubkeys
WISP_SPIDER_ENABLED=true \
WISP_SPIDER_RELAYS="wss://relay.damus.io,wss://nos.lol" \
WISP_SPIDER_PUBKEYS="3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d" \
./zig-out/bin/wisp

# Or follow an admin's contact list (kind 3)
WISP_SPIDER_ENABLED=true \
WISP_SPIDER_RELAYS="wss://relay.damus.io" \
WISP_SPIDER_ADMIN="3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d" \
./zig-out/bin/wisp
```

## License

LGPL-2.1-or-later
