# Configuration

Wisp reads configuration from several sources, applied in order, each overriding the last:

1. **Built-in defaults** (shown in the tables below).
2. **A TOML file**, if you pass one: `wisp relay wisp.toml`.
3. **Environment variables** (`WISP_*`), which override the file.
4. **A few CLI flags** (`--spider-admin`, `--db`), which override everything for the settings they touch.

So an environment variable always wins over the same setting in the TOML file. Copy
[`wisp.toml.example`](https://github.com/privkeyio/wisp/blob/main/wisp.toml.example) to
`wisp.toml` to start from an annotated template.

```sh
WISP_PORT=8080 ./zig-out/bin/wisp
```

## Command line

```
wisp [command] [config.toml]

Commands:
  relay [config]   Start the relay server (default if omitted)
  import           Import events from stdin (JSONL)
  export           Export all events to stdout (JSONL)
  help             Show help

Flags:
  --spider-admin <npub|hex>   Enable spider mode and follow this pubkey's contacts
  --db <path>                 Database path for import/export (default ./data)
```

The relay's storage path comes from `[storage] path` / `WISP_STORAGE_PATH`. `--db` applies
to the `import` and `export` commands only. `--spider-admin` accepts an `npub` (decoded to
hex), unlike the file/env spider settings which expect raw hex.

## Settings

Each setting lists its TOML key (under its `[section]`), its environment variable, type, and
default. Settings with no environment variable are configurable only via the TOML file.

Booleans accept `true`/`false`, `1`/`0`, `yes`/`no` and `on`/`off`, case-insensitively.

Invalid values are treated differently depending on where they come from. In the TOML file
they fail the load, naming the file, line, section and key, since the file is authored
deliberately. In an environment variable they log a warning and the previous value is kept,
because these usually come from an orchestrator where refusing to boot turns a typo into a
crash loop. Either way the value is never discarded silently, so check the log after changing
a limit if you want to be sure it took effect.

### `[server]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `host` | `WISP_HOST` | string | `127.0.0.1` | Bind address. Use `0.0.0.0` only behind a reverse proxy. |
| `port` | `WISP_PORT` | u16 | `7777` | Listen port. HTTP (NIP-11, NIP-86, `/metrics`) and WebSocket share this one port. |

### `[relay]` (NIP-11 metadata)

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `name` | `WISP_RELAY_NAME` | string | `Wisp` | Relay name advertised in NIP-11. |
| `description` | — | string | `A lightweight Nostr relay` | NIP-11 description. |
| `pubkey` | — | hex | (unset) | Operator pubkey in NIP-11. |
| `contact` | — | string | (unset) | Operator contact in NIP-11. |

### `[storage]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `path` | `WISP_STORAGE_PATH` | string | `./data` | LMDB data directory. Point at `/dev/shm/wisp/data` (tmpfs) for lowest latency; data is then lost on reboot (see warning). |
| `map_size_mb` | — | u32 | `10240` | LMDB maximum map size in MB. The hard upper bound on database size. |
| `sync` | `WISP_STORAGE_SYNC` | enum | `meta` | Write durability: `none`, `meta`, or `full`. See [Durability](#durability). |

> **Warning:** `/dev/shm` is volatile tmpfs — all data is lost on reboot. Use it only for
> benchmarks or disposable caches. For production, point `path` at persistent storage and/or
> configure backups.

#### Durability

`sync` controls how aggressively LMDB flushes to disk on each commit, trading throughput for
crash safety:

| Mode | Behavior | On crash / power loss |
|------|----------|-----------------------|
| `none` | `MDB_NOSYNC` + `MDB_NOMETASYNC`: no flush on commit. Fastest. | Recent commits can be lost, and the database can be corrupted. |
| `meta` (default) | Flush data on every commit, defer only the metapage fsync. | The last transaction may roll back, but the database stays consistent. |
| `full` | Fsync on every commit. Durable. | No acknowledged write is lost. |

In the durable modes (`meta`/`full`) writes go through a group-commit writer
thread: events that arrive close together are committed in one transaction, so a
batch pays a single fsync rather than one per event. Throughput therefore scales
with how many clients publish concurrently.

The default is `meta`: it never corrupts the database and at worst loses the last
transaction on a crash. Use `full` when no acknowledged write may ever be lost, or
`none` for maximum throughput on a relay where the data is disposable (a cache or
benchmark) and a crash may corrupt the database. `none` uses a faster synchronous
write path, since there is no fsync to amortize.

### `[limits]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `max_connections` | `WISP_MAX_CONNECTIONS` | u32 | `1000` | Maximum concurrent connections. |
| `workers` | `WISP_WORKERS` | u16 | `0` | Epoll worker threads. `0` = auto (`min(CPU, 4)`). Set `1` on a personal or memory-constrained relay to shed per-worker buffers and threads. |
| `max_conn` | `WISP_MAX_CONN` | u16 | `0` | Live connections **per worker** before that worker pauses accepting. `0` keeps the built-in default (8192). Distinct from `max_connections`, which is the relay-wide cap. Accepted connections are limited by `max_conn` × the effective worker count (with `workers = 0` that is `min(CPU, 4)`, not `0`), while `max_connections` independently caps registered relay connections; whichever binds first applies. |
| `max_subscriptions` | — | u32 | `20` | Maximum open REQ subscriptions per connection. |
| `max_filters` | — | u32 | `10` | Maximum filters per REQ. |
| `max_message_size` | — | u32 | `65536` | Maximum inbound WebSocket message size, in bytes. |
| `max_event_tags` | — | u32 | `2000` | Maximum tags per event. |
| `max_content_length` | — | u32 | `102400` | Maximum event `content` length, in bytes. |
| `query_limit_default` | — | u32 | `500` | Events returned per REQ when the client sets no `limit`. |
| `query_limit_max` | — | u32 | `5000` | Hard cap on events returned per REQ. |
| `query_scan_multiplier` | `WISP_QUERY_SCAN_MULTIPLIER` | u32 | `20` | Caps entries scanned per query at `limit × multiplier` before stopping, so a selective filter cannot page-fault the whole event DB. `0` disables the cap. |
| `max_event_age` | — | i64 (seconds) | `94608000` | Reject events whose `created_at` is older than this (default 3 years). |
| `max_future_seconds` | — | i64 (seconds) | `900` | Reject events dated more than this far in the future (default 15 minutes). |
| `min_pow_difficulty` | `WISP_MIN_POW_DIFFICULTY` | u8 | `0` | Required NIP-13 proof-of-work leading-zero bits. `0` disables. |

### `[watchdog]`

Detects a wedged accept loop: a state where the kernel completes TCP handshakes
but the relay never services them, leaving the process alive at near-zero CPU
while every connection hangs. A background thread opens a loopback connection to
the relay's own listener and expects any HTTP reply. After `failures`
consecutive stalls it terminates the process so a supervisor restarts it.

**This means the relay can exit on its own.** It only does so when it has
answered at least one probe successfully (so a slow start or an environment where
loopback probing cannot work never triggers it), and never when the relay
accepted a connection since the previous probe. Connection refusals and local
descriptor exhaustion are logged but never counted, since a restart fixes
neither. Set `enabled = false` to opt out entirely.

The accept check is what makes this specifically an *accept-loop* watchdog. httpz
counts an accept before any handler runs, so a probe that is accepted and then
goes unanswered vetoes itself: a relay whose handlers are slow or whose thread
pool is saturated is degraded rather than wedged, and restarting it would turn a
slowdown into an outage. Only a relay that never accepts the probe at all can
reach the exit path. `httpz_connections` on `/metrics` is that same accept
counter, so comparing it against `wisp_connections_total` (completed WebSocket
upgrades) shows whether the accept loop is running while work backs up.

Because the process exits deliberately, run wisp under something that restarts
it (`--restart unless-stopped` for Docker, `Restart=always` for systemd).
Without a supervisor, a wedge that used to leave a degraded relay running will
instead leave it stopped.

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `enabled` | `WISP_WATCHDOG_ENABLED` | bool | `true` | Enable the self-probe. |
| `interval_seconds` | `WISP_WATCHDOG_INTERVAL_SECONDS` | u32 | `10` | Seconds between probes. Values below `1` are clamped to `1`. |
| `timeout_ms` | `WISP_WATCHDOG_TIMEOUT_MS` | u32 | `2000` | Deadline for a single probe, covering connect, send and reply. Clamped to `100`–`5000`; the upper bound also caps how long a shutdown can wait on a probe already in flight. |
| `failures` | `WISP_WATCHDOG_FAILURES` | u32 | `3` | Consecutive stalled probes before exiting. **Raised automatically** when `interval_seconds × failures` would be short enough to fire before the relay reaps stalled connections, so that connection pressure cannot force a restart. At `interval_seconds = 1` the effective value becomes 26; the raise is logged at startup. The shipped defaults are already sufficient and are left untouched. |

### `[rate_limits]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `events_per_minute` | `WISP_EVENTS_PER_MINUTE` | u32 | `120` | Per-IP event publish rate (token bucket). `0` disables. |
| `queries_per_minute` | `WISP_QUERIES_PER_MINUTE` | u32 | `300` | Per-IP limit on expensive query messages (REQ / COUNT / NEG_OPEN). `0` disables. |

### `[timeouts]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `idle_seconds` | `WISP_IDLE_SECONDS` | u32 | `300` | Close a connection after this many seconds with no activity. |

### `[auth]` (NIP-42)

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `required` | `WISP_AUTH_REQUIRED` | bool | `false` | Require NIP-42 AUTH before any read or write. |
| `to_write` | `WISP_AUTH_TO_WRITE` | bool | `false` | Require NIP-42 AUTH before publishing events. |
| `relay_url` | `WISP_RELAY_URL` | string | (empty) | Canonical relay URL bound into the AUTH challenge. Set this to your public `wss://` URL when auth is enabled. |

### `[security]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `trust_proxy` | `WISP_TRUST_PROXY` | bool | `false` | Honor `X-Forwarded-For` / `X-Real-IP` for the client IP. Enable only behind a reverse proxy whose backend port is not directly reachable, or clients can spoof their IP. |
| `trusted_proxies` | `WISP_TRUSTED_PROXIES` | csv | (empty) | IPs/prefixes of proxies whose forwarded headers are trusted. Empty with `trust_proxy=true` trusts any peer. |
| `max_connections_per_ip` | `WISP_MAX_CONNECTIONS_PER_IP` | u32 | `10` | Per-IP concurrent connection cap, applied at the WebSocket upgrade. A connection that never sends a request does not reach it; those are closed by the 10s request timeout instead. To cap concurrent TCP connections per source, see [Limiting connections per source](deployment.md#limiting-connections-per-source). |
| `ip_whitelist` | `WISP_IP_WHITELIST` | csv | (empty) | If set, only these IPs/prefixes may connect. |
| `ip_blacklist` | `WISP_IP_BLACKLIST` | csv | (empty) | These IPs/prefixes are refused. |

IP list entries match exactly unless they end in `.` (IPv4 prefix) or `:` (IPv6 prefix), e.g.
`10.0.0.` matches `10.0.0.0`–`10.0.0.255`. CIDR notation and `*` wildcards are not supported.

### `[spider]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `enabled` | `WISP_SPIDER_ENABLED` | bool | `false` | Enable spider sync. |
| `relays` | `WISP_SPIDER_RELAYS` | csv | (empty) | Upstream relay URLs to pull from. |
| `admin` | `WISP_SPIDER_ADMIN` | hex | (empty) | Pubkey whose contact list seeds the follow set. |
| `pubkeys` | `WISP_SPIDER_PUBKEYS` | csv | (empty) | Additional hex pubkeys to follow. |
| `sync_interval` | `WISP_SPIDER_SYNC_INTERVAL` | u32 (seconds) | `300` | Seconds between sync passes. |

### `[negentropy]` (NIP-77)

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `enabled` | `WISP_NEGENTROPY_ENABLED` | bool | `true` | Enable NIP-77 set reconciliation. |
| `max_sync_events` | `WISP_NEGENTROPY_MAX_SYNC_EVENTS` | u32 | `1000000` | Maximum event IDs buffered per reconciliation session. |
| `max_sessions` | `WISP_NEGENTROPY_MAX_SESSIONS` | u32 | `4` | Concurrent reconciliation sessions per connection. Each can buffer up to `max_sync_events` IDs, so keep this small. |

### `[management]` (NIP-86)

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `admin_pubkeys` | `WISP_ADMIN_PUBKEYS` | csv | (empty) | Hex pubkeys allowed to run NIP-86 relay-management commands (ban/allow pubkeys and IPs, etc.). |

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

## Monitoring

Operational metrics are served in Prometheus format at `GET /metrics` on the relay port:
connection counts, events stored/rejected/broadcast, REQ totals, and rate-limit counters. The
endpoint honors `ip_whitelist`/`ip_blacklist`, so restrict it there or at your reverse
proxy/firewall if it should not be public.

The `httpz_*` series come from the embedded HTTP server. The useful one is
`httpz_connections`, which counts accepted TCP connections before any handler runs. Read
against `wisp_connections_total` (completed WebSocket upgrades) it separates two states that
look identical from outside: if accepts climb while upgrades stall, the accept loop is running
and work is backing up; if accepts stop climbing while clients are still connecting, the accept
loop itself is stuck. `httpz_timeout_request` and `httpz_timeout_keepalive` count connections
reaped for holding a slot without completing a request.
