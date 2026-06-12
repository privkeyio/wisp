# Configuration

Copy `wisp.toml.example` to `wisp.toml` and customize. A subset of options can also be
overridden with a `WISP_`-prefixed environment variable (e.g. `WISP_PORT`,
`WISP_STORAGE_PATH`, `WISP_MAX_CONNECTIONS`, `WISP_EVENTS_PER_MINUTE`). See `loadEnv` in
[`src/config.zig`](https://github.com/privkeyio/wisp/blob/main/src/config.zig) for the
authoritative list of supported variables:

```sh
WISP_PORT=8080 ./zig-out/bin/wisp
```

See [`wisp.toml.example`](https://github.com/privkeyio/wisp/blob/main/wisp.toml.example) for
the full, annotated list of options. The main sections:

| Section | Purpose |
|---------|---------|
| `[server]` | Listen `host` and `port` (default `0.0.0.0:7777`). |
| `[relay]` | Public relay metadata: `name`, `description`, `pubkey`, `contact`. |
| `[storage]` | LMDB data `path` and map size. Point at `/dev/shm` (tmpfs) for ~2x lower latency, but note it is volatile (see warning below). |
| `[limits]` | Connection, subscription, filter, message-size, and query limits. |
| `[rate_limits]` | Per-relay event rate (`events_per_minute`). |
| `[timeouts]` | Idle connection timeout. |
| `[auth]` | Optional NIP-42 authentication for reads and/or writes. |
| `[security]` | Per-IP rate limits, proxy trust, and IP allow/deny lists. |
| `[spider]` | Sync events for followed pubkeys from external relays. |
| `[negentropy]` | NIP-77 set-reconciliation sync. |

> **Warning:** `/dev/shm` is volatile tmpfs — all data is lost on reboot. Use it only for
> benchmarks or disposable caches. For production, point `path` at persistent storage (a
> real disk or persistent volume) and/or configure backups.

## Spider mode

Spider mode keeps your relay populated by syncing events from the people you follow. Set
`admin` to your hex pubkey (or pass `--spider-admin npub1...` on the CLI) and Wisp fetches
your contact list and mirrors their notes from the configured `relays`:

```toml
[spider]
enabled = true
relays = "wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band"
sync_interval = 300
admin = ""  # your hex pubkey
```
