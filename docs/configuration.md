# Configuration

Copy `wisp.toml.example` to `wisp.toml` and customize, or override any option with a
`WISP_`-prefixed environment variable:

```sh
WISP_PORT=8080 ./zig-out/bin/wisp
```

See [`wisp.toml.example`](https://github.com/privkeyio/wisp/blob/main/wisp.toml.example) for
the full, annotated list of options. The main sections:

| Section | Purpose |
|---------|---------|
| `[server]` | Listen `host` and `port` (default `0.0.0.0:7777`). |
| `[relay]` | Public relay metadata: `name`, `description`, `pubkey`, `contact`. |
| `[storage]` | LMDB data `path` and map size. Point at `/dev/shm` (tmpfs) for ~2x lower latency. |
| `[limits]` | Connection, subscription, filter, message-size, and rate limits. |
| `[timeouts]` | Idle connection timeout. |
| `[auth]` | Optional NIP-42 authentication for reads and/or writes. |
| `[security]` | Per-IP rate limits, proxy trust, and IP allow/deny lists. |
| `[spider]` | Sync events for followed pubkeys from external relays. |
| `[negentropy]` | NIP-77 set-reconciliation sync. |

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
