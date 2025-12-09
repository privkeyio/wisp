# Wisp

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A minimal Nostr relay in Zig. Uses [libnostr-c](https://github.com/privkeyio/libnostr-c) for protocol handling and LMDB for storage.

Supports NIPs: 1, 9, 11, 40

## Building

```sh
# Install dependencies (Debian/Ubuntu)
sudo apt install -y libssl-dev libcjson-dev libsecp256k1-dev liblmdb-dev

# Clone
git clone https://github.com/privkeyio/wisp && cd wisp/
git clone https://github.com/privkeyio/libnostr-c ../libnostr-c

# Build
zig build
```

## Running

```sh
./zig-out/bin/wisp
```

Listens on `127.0.0.1:7777` by default.

## Configuration

Configure via `wisp.toml` or environment variables:
- `WISP_PORT` - Port to listen on (default: 7777)
- `WISP_HOST` - Host to bind to (default: 127.0.0.1)
- `WISP_DATA_DIR` - Data directory (default: ./data)

## License

LGPL-2.1-or-later
