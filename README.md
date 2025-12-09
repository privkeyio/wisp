# Wisp

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A minimal Nostr relay in Zig. Uses [libnostr-c](https://github.com/privkeyio/libnostr-c) for protocol handling and LMDB for storage.

Supports NIPs: 1, 9, 11, 40

## Requirements

- Zig 0.13+
- libnostr-c (built, in `../libnostr-c`)
- liblmdb (`apt install liblmdb-dev`)

## Build

```sh
zig build
```

## Run

```sh
LD_LIBRARY_PATH=../libnostr-c/build ./zig-out/bin/wisp
```

Listens on `127.0.0.1:7777` by default. Configure via `wisp.toml` or environment variables (`WISP_PORT`, `WISP_HOST`, `WISP_DATA_DIR`).

## License

LGPL-2.1-or-later
