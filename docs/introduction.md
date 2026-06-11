# Wisp

*A fast, lightweight [Nostr](https://github.com/nostr-protocol/nostr) relay written in Zig.*

Wisp is a single-binary Nostr relay built for speed and simplicity. One command runs your
personal relay, automatically syncing notes from the people you follow.

## Why Wisp?

- **Fast** — 2x higher throughput than strfry, 10x lower latency.
- **Small** — single 1.2MB binary, ~15MB RAM at idle.
- **Simple** — one command to run your personal relay with your feed.
- **Spider Mode** — automatically syncs events from people you follow.

## Features

- NIPs: 1, 2, 9, 11, 13, 16, 33, 40, 42, 45, 50, 65, 70, 77, 86
- LMDB storage (no external database)
- Spider mode for syncing events from external relays
- Import/export to JSONL

## Where to start

- **[Installation](./installation.md)** — Docker, build from source, and import/export.
- **[Configuration](./configuration.md)** — `wisp.toml` and `WISP_`-prefixed environment variables.
- **[Deployment](./deployment.md)** — exposing your relay publicly over `wss://` with Caddy.
- **[Benchmarks](./benchmarks.md)** — throughput and latency versus strfry.
- **[Contributing](./contributing.md)** — reporting issues and submitting pull requests.

## Project links

- Source: <https://github.com/privkeyio/wisp>
- License: [MIT](https://github.com/privkeyio/wisp/blob/main/LICENSE)
