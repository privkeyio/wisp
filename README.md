# wisp - a lightweight nostr relay

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A lightweight [nostr](https://github.com/nostr-protocol/nostr) relay written in Zig.

* Supports NIPs: 1, 9, 11, 40, 42
* LMDB storage (no external database)
* [noscrypt](https://github.com/VnUgE/noscrypt) for Schnorr signatures
* Single binary, minimal dependencies
* Requires Zig 0.15+

## Build

```sh
# Debian/Ubuntu
sudo apt install -y libssl-dev libsecp256k1-dev liblmdb-dev

git clone https://github.com/privkeyio/wisp && cd wisp/
git clone https://github.com/VnUgE/noscrypt ../noscrypt
zig build
```

## Run

```sh
./zig-out/bin/wisp
```

Listens on `127.0.0.1:7777`, stores data in `./data/`.

## Configure

Environment variables:

| Variable | Default |
|----------|---------|
| `WISP_HOST` | `127.0.0.1` |
| `WISP_PORT` | `7777` |
| `WISP_STORAGE_PATH` | `./data` |
| `WISP_AUTH_TO_WRITE` | `false` |
| `WISP_RELAY_URL` | `` |
| `WISP_EVENTS_PER_MINUTE` | `60` |

Or use a config file (`wisp.toml`):

```toml
[server]
host = "0.0.0.0"
port = 7777

[relay]
name = "My Relay"

[limits]
events_per_minute = 60

[auth]
to_write = true
relay_url = "wss://relay.example.com"
```

## License

LGPL-2.1-or-later
