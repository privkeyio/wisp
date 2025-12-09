# Wisp

<img src="assets/wisp-logo.jpeg" alt="Wisp Logo" width="300">

A minimal Nostr relay in Zig. Uses [libnostr-c](https://github.com/privkeyio/libnostr-c) for protocol handling and LMDB for storage.

## Requirements

- Zig 0.13+
- libnostr-c (built, in `../libnostr-c`)
- liblmdb (`apt install liblmdb-dev`)

## Build

```sh
zig build
```

## Test

```sh
LD_LIBRARY_PATH=../libnostr-c/build zig build test-nostr
zig build test-lmdb
```

## Status

Work in progress. Core FFI bindings verified working.
