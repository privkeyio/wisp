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
| `max_connections` | `WISP_MAX_CONNECTIONS` | u32 | `1000` | Maximum concurrent connections. See [When max_connections is full](#when-max_connections-is-full). |
| `reserved_connections` | `WISP_RESERVED_CONNECTIONS` | u32 | `0` | The top this-many `max_connections` slots are granted only to clients matching `reserved_ips`, so health checks and trusted clients still get in when the pool is full. Must be less than `max_connections` or startup fails. `0` disables it. |
| `evict_idle_seconds` | `WISP_EVICT_IDLE_SECONDS` | u32 | `120` | On by default. When `max_connections` is full, a new client evicts the longest-idle connection that has no open subscription or NIP-77 session and has sent no message for at least this many seconds, instead of getting `503`. `0` disables eviction. See [When max_connections is full](#when-max_connections-is-full) for who can be evicted. |
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
| `failures` | `WISP_WATCHDOG_FAILURES` | u32 | `4` | Consecutive stalled probes before exiting. **Raised automatically** when `(failures - 1) × interval_seconds`, the time from the first stalled probe to the last, would be shorter than the time the relay takes to reap stalled connections (25s), so that connection pressure cannot force a restart. At `interval_seconds = 1` the effective value becomes 26; the raise is logged at startup. The shipped defaults are already sufficient and are left untouched. |

### `[rate_limits]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `events_per_minute` | `WISP_EVENTS_PER_MINUTE` | u32 | `120` | Per-IP event publish rate (token bucket). `0` disables. |
| `queries_per_minute` | `WISP_QUERIES_PER_MINUTE` | u32 | `300` | Per-IP limit on expensive query messages (REQ / COUNT / NEG_OPEN). `0` disables. |

### `[timeouts]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `idle_seconds` | `WISP_IDLE_SECONDS` | u32 | `300` | Close a connection after this many seconds without a well-formed client message. WebSocket pings and frames that fail to parse do not count. |

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
| `trusted_proxies` | `WISP_TRUSTED_PROXIES` | csv | (empty) | IPs/CIDR ranges of proxies whose forwarded headers are trusted. Empty with `trust_proxy=true` trusts any peer. |
| `metrics_public` | `WISP_METRICS_PUBLIC` | bool | `false` | Serve `/metrics` to any client. When `false`, only direct requests whose socket peer is 127.0.0.0/8 or `::1` (including `::ffff:127.x`) and that carry no `X-Forwarded-For`/`X-Real-IP` header may scrape it; others get 403. |
| `max_connections_per_ip` | `WISP_MAX_CONNECTIONS_PER_IP` | u32 | `10` | Per-IP concurrent connection cap, applied at the WebSocket upgrade. A connection that never sends a request does not reach it; those are closed by the 10s request timeout instead. To cap concurrent TCP connections per source, see [Limiting connections per source](deployment.md#limiting-connections-per-source). |
| `max_connections_per_subnet` | `WISP_MAX_CONNECTIONS_PER_SUBNET` | u32 | `50` | Concurrent connection cap shared by every client in one subnet (sized by the two prefix settings below), applied alongside `max_connections_per_ip`: a connection must fit under both. Stops a swarm spread over many addresses in one range from exhausting `max_connections`. `0` disables it. A value below `max_connections_per_ip` is raised to it, so one address can always use its full per-IP allowance. 50 per /24 is generous for real users, including CGNAT and mobile carriers. |
| `subnet_prefix_v4` | `WISP_SUBNET_PREFIX_V4` | u8 | `24` | IPv4 prefix length (0-32) that groups clients for `max_connections_per_subnet`. IPv4-mapped IPv6 clients (`::ffff:a.b.c.d`) count in their IPv4 subnet. |
| `subnet_prefix_v6` | `WISP_SUBNET_PREFIX_V6` | u8 | `48` | IPv6 prefix length (0-128) that groups clients for `max_connections_per_subnet`. |
| `ip_whitelist` | `WISP_IP_WHITELIST` | csv | (empty) | If set, only these IPs/CIDR ranges may connect. |
| `ip_blacklist` | `WISP_IP_BLACKLIST` | csv | (empty) | These IPs/CIDR ranges are refused. |
| `reserved_ips` | `WISP_RESERVED_IPS` | csv | (empty) | IPs/CIDR ranges that may use the `reserved_connections` slots and are never evicted, e.g. your uptime monitor. This is the only list that grants reserved status; `ip_whitelist` only decides who may connect. Matched against the same client IP as the per-IP limit, so behind a proxy it needs `trust_proxy`. While a request's forwarding headers are not honored (`trust_proxy` off, or the peer is not in `trusted_proxies`), a request that carries `X-Forwarded-For` or `X-Real-IP` is never reserved, since its address is the proxy's. Startup warns if this list covers a loopback or private range while `trust_proxy` is off. |

IP list entries are a single address (`10.0.0.5`, `2001:db8::1`) or a CIDR range
(`185.220.100.0/22`, `2001:db8::/32`, `0.0.0.0/0`). Bits past the prefix length are ignored, so
`10.1.2.3/8` means `10.0.0.0/8`. An IPv4 rule also matches the same client seen as an
IPv4-mapped IPv6 address (`::ffff:185.220.101.1`); IPv6 rules match only IPv6 clients, so `::/0`
does not cover IPv4.

Older prefix entries ending in `.` or `:` still work and are read as the equivalent CIDR range:
`10.` is `10.0.0.0/8`, `192.168.` is `192.168.0.0/16`, `185.220.101.` is `185.220.101.0/24`, and
each IPv6 group before the trailing `:` is 16 bits, so `2001:db8:` is `2001:db8::/32`. A mapped
prefix is the IPv4 range it embeds: `::ffff:185.220.101.` is `185.220.101.0/24`. An IPv6 prefix
containing `::` (`2001:db8::1:`) is no longer accepted, because its length is ambiguous; write it
as a CIDR range instead.

An entry that is none of these, such as `192.168.*`, `10.0.0.0/33` or a hostname, is rejected at
startup with a warning naming it rather than being accepted and then matching nothing. If every
`ip_whitelist` entry is rejected the allow list stays enabled and admits no one. The same rules
apply to `trusted_proxies` and to the NIP-86 `blockip` method, which answers `400` for an entry it
cannot parse.

### When max_connections is full

A WebSocket upgrade is admitted in this order: `ip_whitelist`/`ip_blacklist`, then
`max_connections_per_ip` and `max_connections_per_subnet` (`429`), then the global pool.
In the pool:

1. A client matching `reserved_ips` may use every slot. Any other client, including one
   matching `ip_whitelist`, may only use `max_connections - reserved_connections`.
2. If no slot is free for the newcomer, the longest-idle connection is closed to make room.
   It must have no open REQ subscription and no open NIP-77 (negentropy) session, must not
   have sent a well-formed message for `evict_idle_seconds`, and must not be a reserved
   client. A client that is subscribed, syncing or recently active is never evicted.
3. If no connection qualifies, the newcomer gets `503 server connection limit reached`, as before.

Eviction is on by default (`evict_idle_seconds = 120`); set it to `0` to turn it off. It only
happens while the pool is full. Once a connection has been silent for `evict_idle_seconds`, these
clients can be evicted under that pressure and are expected to reconnect:

- publish-only clients that hold a connection open between events, with no subscription;
- NIP-42 sessions that authenticated (`AUTH`) and then sent nothing else;
- clients that query with `REQ`, wait for `EOSE`, `CLOSE` the subscription and stay connected
  idle until their next query.

A NIP-77 sync holds an open session from `NEG-OPEN` until `NEG-CLOSE` (or an error) and is not
evicted while it does. WebSocket pings, and frames that are not a well-formed Nostr message, do
not count as messages. Under `auth_required`, `REQ`, `COUNT` and `NEG-OPEN` are refused until the
client authenticates, so an unauthenticated connection cannot protect itself with a subscription.

Eviction only runs after the per-IP and per-subnet caps have admitted the newcomer, so a source
can never evict other clients with connections it was not allowed to hold. It stops only a silent
swarm: connections that connect and sit idle give way to new clients long before `idle_seconds`
would reap them. A swarm that keeps every connection busy, by holding a subscription open or
sending a cheap well-formed message more often than `evict_idle_seconds`, is never evicted and
still fills the pool. Against that, the real defenses are `max_connections_per_subnet` (and
`max_connections_per_ip`), which bound how much of the pool one network can take, and
`reserved_connections` with `reserved_ips`, which keep the relay reachable for your own clients.

There is no separate limit on how often one source can evict: a client that connects, takes an
idle connection's slot and disconnects can repeat that, one eviction per connection it opens,
within its per-IP and per-subnet caps. It can only ever remove connections that already meet the
rules above.

When an upgrade finds no evictable connection, the relay skips the search for the next second, so
a flood of refused upgrades costs one scan a second rather than one per attempt. A connection that
becomes evictable by closing its last subscription or NIP-77 session is considered at once.
Evictions are counted in `wisp_connections_evicted_total` and logged at most once a minute, as a
count; a count still pending when evictions stop is logged within that minute.

### `[spider]`

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `enabled` | `WISP_SPIDER_ENABLED` | bool | `false` | Enable spider sync. |
| `relays` | `WISP_SPIDER_RELAYS` | csv | (empty) | Upstream relay URLs to pull from. |
| `admin` | `WISP_SPIDER_ADMIN` | hex | (empty) | Pubkey whose contact list seeds the follow set. |
| `pubkeys` | `WISP_SPIDER_PUBKEYS` | csv | (empty) | Additional hex pubkeys to follow. |
| `sync_interval` | `WISP_SPIDER_SYNC_INTERVAL` | u32 (seconds) | `300` | Seconds between sync passes. |
| `mention_events_per_minute` | `WISP_SPIDER_MENTION_EVENTS_PER_MINUTE` | u32 | `600` | Per upstream relay, how many events per minute are stored that arrive only because they p-tag a follow (their authors are not followed, so anyone can create them). Events by follows and the admin are not limited. `0` removes the limit. |

### `[negentropy]` (NIP-77)

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `enabled` | `WISP_NEGENTROPY_ENABLED` | bool | `true` | Enable NIP-77 set reconciliation. |
| `max_sync_events` | `WISP_NEGENTROPY_MAX_SYNC_EVENTS` | u32 | `100000` | Maximum event IDs buffered in memory per reconciliation session, about 40 bytes each (roughly 4 MB at the default). A session whose filter matches more events is refused with `NEG-ERR "blocked: too many events"` rather than reconciled partially. A selective filter can instead hit the scan cap (`max_sync_events × query_scan_multiplier` index entries) first and get `NEG-ERR "error: result set too large to reconcile"`; raising either setting fixes it. Raise it when peers sync large stores relay-to-relay with NIP-77, keeping in mind that every session on every connection can buffer this many. |
| `max_sessions` | `WISP_NEGENTROPY_MAX_SESSIONS` | u32 | `4` | Concurrent reconciliation sessions per connection. Each can buffer up to `max_sync_events` IDs, so keep this small. |

### `[management]` (NIP-86)

| TOML | Env | Type | Default | Description |
|------|-----|------|---------|-------------|
| `admin_pubkeys` | `WISP_ADMIN_PUBKEYS` | csv | (empty) | Pubkeys (64-character hex in any case, or `npub`) allowed to run NIP-86 relay-management commands (ban/allow pubkeys and IPs, etc.). An entry that is neither is logged at startup and grants nothing. |

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
connection counts, events stored/rejected/broadcast, REQ totals, and rate-limit counters. By
default it is served only to direct requests: the TCP peer must be loopback (127.0.0.0/8, `::1`)
and the request must carry neither `X-Forwarded-For` nor `X-Real-IP`. Everyone else gets 403.
Set `metrics_public = true` under `[security]` (`WISP_METRICS_PUBLIC=true`) to open it to any
client that passes `ip_whitelist`/`ip_blacklist`, which still apply either way.

Reverse proxy note: the check looks at the raw socket peer, never at forwarded addresses, so
`trust_proxy` and `trusted_proxies` do not affect `/metrics`. A proxy that adds `X-Forwarded-For`
(Caddy and the nginx example in [deployment.md](deployment.md) both do) has its requests
refused, and a client cannot get in by forging a forwarding header. A request whose headers
fill wisp's 32-header table is also refused, since an overflowing request may have lost the
proxy's header. Scrape the backend port directly from the host instead. Denying `/metrics` at the
proxy is still recommended as defence in depth, in case a proxy forwards without adding either
header (e.g. nginx `location = /metrics { return 404; }`, Caddy `respond /metrics 404`).

The `httpz_*` series come from the embedded HTTP server. The useful one is
`httpz_connections`, which counts accepted TCP connections before any handler runs. Read
against `wisp_connections_total` (completed WebSocket upgrades) it separates two states that
look identical from outside: if accepts climb while upgrades stall, the accept loop is running
and work is backing up; if accepts stop climbing while clients are still connecting, the accept
loop itself is stuck. `httpz_timeout_request` and `httpz_timeout_keepalive` count connections
reaped for holding a slot without completing a request.
