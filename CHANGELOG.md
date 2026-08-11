# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-08-11

Correctness and hardening across the query, reconciliation and configuration
paths, found while verifying the watchdog work that went into 0.5.15.

The theme is silence: a failed storage read was reported as a finished result
set, a negentropy session sealed and reconciled a partial one, config values
that could never take effect were accepted without a word, and a write that
failed partway left a truncated frame on a connection that stayed open. Each of
those now says so.

Two changes can alter behavior on upgrade; see the upgrade notes below before
rolling out.

### Changed

- Bumped libnostr-z to v0.3.7 to pick up a negentropy storage fix. Loading records into a reconciliation session was O(n^2), because each insert moved every element after it and wisp enumerates a newest-first index, so every record landed at the front and shifted the whole array. Serving a NEG-OPEN over a large match set spent that time on a handler thread while the peer waited (#178)

### Added

- `/metrics` now also exposes httpz's own counters. `httpz_connections` counts accepted TCP connections before any handler runs, so reading it against `wisp_connections_total` (completed WebSocket upgrades) distinguishes an accept loop that is running while work backs up from one that is stuck (#168)

### Fixed

- A connection whose write fails is now closed instead of left in place. The WebSocket write path drains its buffer as it goes and only reports the error afterwards, so a write that fails partway has already put a truncated frame on the wire; callers cannot tell how much went out, and every one of them skipped past the failure, so the next message written to that connection was appended into a desynchronized frame stream and the client saw garbage from then on (#175)

- A negentropy match set of exactly `negentropy_max_sync_events` is no longer rejected as too large. The serving side asked the store for exactly the cap, and the iterator stops once it has returned that many events, so a complete set at the cap was indistinguishable from one exceeding it and got `NEG-ERR blocked: too many events`. It now asks for one more event, which is what tells the two apart (#174)

- An `ip_whitelist`, `ip_blacklist` or `trusted_proxies` entry that can never match is now rejected at load with a warning naming it, instead of being stored and silently matching nothing. CIDR (`10.0.0.0/8`) and globs (`192.168.*`) are the usual way this happened: both look correct, neither is supported, and on a deny list the result was fail-open, with the operator believing a range was blocked when it was not. On `trusted_proxies` it failed the other way, collapsing every client behind the proxy into one rate-limit bucket (#173)

- A failed storage read is no longer reported as a finished result set. An iterator error was swallowed as "no more events" on all three query paths, so REQ sent EOSE over a partial set, NEG-OPEN sealed and reconciled one (making the relay report events as missing that it actually holds), and COUNT answered with a number a failed read had lowered. Each now reports the failure instead (#172)
- NEG-OPEN no longer holds an LMDB read transaction open while replying. Enumeration ran inside a transaction scoped to the whole function, so the reconciliation reply, a 128 KiB frame written to a client that may be slow to take it, went out with the transaction still live, and LMDB cannot reclaim a page freed after a transaction started for as long as it lives. Enumeration is now scoped so the transaction is released before anything is written. The error replies on this path were affected the same way (#172)

- A REQ that ends early no longer reports success. `EOSE` tells a client it has the whole result set, and it was sent unconditionally, including after a write failure or a skipped event. Streaming now reports how it ended and `EOSE` is sent only on completion; a stream cut short ends with `CLOSED` and a reason, and the subscription is dropped first so the relay does not keep broadcasting to a subscription it just declared closed (#171)
- Result streaming is bounded by a wall-clock budget as a backstop on how long a REQ can hold an LMDB read transaction open, which blocks free-page reclamation for its lifetime. Note the primary bound in the shipped build is that the socket is non-blocking, so a peer that stops reading fails its next write immediately; the budget matters if httpz is ever built in blocking mode. The earlier claim that `SO_SNDTIMEO` bounds these writes was wrong, and the misleading comment has been corrected (#171)

- A malformed `WISP_*` environment variable is no longer ignored in silence. Values that fail to parse now log a warning naming the variable, its value and the value being kept. Previously `WISP_MAX_CONN=70000` (which does not fit its type) or `WISP_WATCHDOG_TIMEOUT_MS=2000ms` left the default in place with no output, so an operator could believe a limit was in force when it was not (#170)
- Booleans are parsed case-insensitively and accept `yes`/`no` and `on`/`off`. Any unrecognized value was previously read as `false`, so `enabled = TRUE` silently turned a setting off, including the watchdog's own switch. In a config file an unrecognized boolean is now an error rather than a silent `false` (#170)
- A bad value in the config file now reports the file, line, section, key and value instead of a bare parse error (#170)
- Warn at startup when `trust_proxy` is enabled with an empty `trusted_proxies`. In that combination `X-Forwarded-For` is honored from any peer, so the IP that keys the deny list and the per-IP connection and rate limits is attacker-chosen (#170)

### Upgrade notes

- Two settings can change meaning on upgrade, both because a value that was previously misread as `false` is now read correctly. **Check `trust_proxy` and `spider.enabled` before upgrading if either is spelled anything other than lowercase `true`/`false`.** For `trust_proxy` this is the one case where the fix turns something *on*: a relay that had been fail-closed only because `TRUE` was misparsed will now honor forwarded headers. The same applies to an empty `WISP_TRUST_PROXY=`, which used to override a file value to `false` and is now treated as unset. The new startup warning fires if the result is the unsafe combination.
- An unrecognized boolean in the config file now fails the load rather than silently meaning `false`. Under a supervisor (`Restart=on-failure`, `--restart unless-stopped`) that is a restart loop until the file is corrected, so validate the config before rolling out. The error names the file, line, section and key. Only the six boolean keys are affected; unknown keys and sections are still ignored, and integer keys already behaved this way.

### Documentation

- Documented how to cap concurrent connections per source address. `max_connections_per_ip` is applied at the WebSocket upgrade, so a connection that never sends a request does not reach it; `docs/deployment.md` now covers enforcing this at the edge, including the fact that the rule belongs on the public port rather than the relay port, since behind a proxy every connection arrives from `127.0.0.1` (#169)

### Fixed

- Handler slowness or a saturated thread pool can no longer escalate to a watchdog restart. The watchdog's liveness veto counts accepts, and httpz counts an accept before any handler runs, so a probe that is accepted and then goes unanswered vetoes itself. That makes it strictly an accept-loop watchdog: only a relay that never accepts the probe at all can reach the exit path (#168)

## [0.5.15] - 2026-08-10

### Added

- Optional accept-loop watchdog: a background thread probes the relay's own listener over loopback and restarts the process if the accept loop wedges. Configurable under `[watchdog]`, and documented including the fact that it can terminate the process and how to turn it off. It is guarded so that ordinary connection pressure cannot trigger it: only "connected, then silence" counts, it will not exit until at least one probe has succeeded, an accept completed since the previous probe vetoes a stall, the probe is bounded end to end, and the failure threshold is raised at startup whenever `interval_seconds x failures` would be short enough to fire before stalled connections are reaped (#165, #166)
- `limits.max_conn` sets the per-worker live-connection cap handed to httpz (#165, #166)
- HTTP request and keepalive timeouts (10s and 15s), so a connection that completes the TCP handshake and then sends nothing cannot hold a worker slot indefinitely. Idle WebSocket clients are unaffected, since a connection leaves both timeout lists once it upgrades (#166)

### Fixed

- Vendored httpz with a patch for a WebSocket accept-stall leak: a closing WebSocket did not release its per-worker connection slot, so a relay would eventually stop accepting. Also guards a union access that could abort the process during connection handover (#165)
- Fixed a connection-slot leak in the vendored httpz timeout sweep, which enabling the request and keepalive timeouts would otherwise have activated. When a sweep found both expired and surviving connections, it removed the expired ones from the tracking list a second time, which silently dropped every survivor from that list: those connections then never timed out and held a worker slot for the life of the process, and the survivor was left pointing at memory the connection pool had already recycled. Staggered idle connections are now each reaped at their own deadline (#166)
- Guarded the vendored httpz connection-slot accounting against underflow, which would panic in `ReleaseSafe` and silently disable the `max_conn` cap in `ReleaseFast` (#166)
- The relay no longer hangs on exit when startup fails. Only the signal handler set the shutdown flag, so an error out of `listen()` left the background threads running and the process blocked joining them (#166)

### Known limitations

- A client that sends a cheap request more often than the 10s request timeout keeps re-arming it and can hold a worker slot indefinitely. Enough such clients still saturate a worker and, sustained past the watchdog's threshold, can still provoke a restart. Bounding this needs a per-IP cap applied at accept time rather than at WebSocket upgrade, which is tracked separately.

## [0.5.14] - 2026-07-20

### Fixed

- Queries are now bounded in how many stored entries they may scan, so a selective filter matching fewer events than its `limit` no longer scans the entire database. Fixes severe CPU and major page-fault load on large databases; the `query_scan_multiplier` config knob (default 20, 0 disables) controls the bound (#160)

## [0.5.13] - 2026-07-16

### Added

- Advertise NIP-51 (lists) in the relay information document, and document + test relay support for Marmot MLS KeyPackage events (#158)

### Changed

- Shard the rate limiters and reuse broadcast scratch buffers to cut worker lock contention under load (#151)

## [0.5.12] - 2026-07-09

### Fixed

- Spider no longer busy-spins a CPU core per quiet `wss://` upstream relay. The TLS read loop retried on 0-plaintext control records (post-handshake NewSessionTicket/KeyUpdate) without re-polling; the pinned websocket.zig now re-polls inside the loop so a quiet socket parks instead of spinning (#145)
- Spider connect and TLS handshake are now bounded by a timeout (default 10s each), so a blackholed or stalling upstream relay can no longer hang the spider thread through shutdown and cause a SIGKILL past the service grace period. Bounds connect + handshake, not DNS resolution (#140 tracks the residual) (#148)

### Changed

- Both fixes land via upstream `karlseguin/websocket.zig` (#103, #108) and `karlseguin/http.zig`; wisp pins upstream, no fork

## [0.5.11] - 2026-07-07

### Added

- Ephemeral events (NIP-16, kinds 20000-29999) are now relayed to matching subscribers in real time instead of being dropped. They are still not stored (#143)
- Nix packaging: a flake with a `wisp` package and a `services.wisp` NixOS module (host option, `LimitNOFILE`, conditional spider sandboxing, effective-port firewall) (#139)

### Fixed

- Spider reconnects half-open upstream relay connections via a staleness watchdog: quiet relays are probed with a keepalive ping (bounded by a write timeout) before a stale-connection reconnect, so silently dropped upstreams recover instead of hanging (#132)
- Spider bootstrap is shutdown-aware and off the accept path: relay connect is gated until the follow list is populated, and the follow list is read under its mutex during the refresh-loop startup (#137)
- Connection reaping hardened with an `SO_KEEPALIVE` backstop and a non-blocking idle reaper, so half-open and idle client connections are reclaimed reliably; TCP keepalive tuning is gated to Linux to avoid macOS corking (#136)
- Zig dependency fetch sets the fetchzip extension so GitHub codeload tarballs unpack correctly (#142)

## [0.5.10] - 2026-07-01

### Changed

- Build against upstream `karlseguin/http.zig` instead of the temporary privkeyio fork. The two fixes the fork carried have merged upstream (the epoll recv-on-freed-Conn fix #216, and the shutdown-buffer join-order fix #217), so the pinned commit is byte-identical to the fork. No functional change from 0.5.9

## [0.5.9] - 2026-06-29

### Fixed

- Relay no longer crashes (SIGSEGV) on shutdown when a query (REQ) was still being served as the relay stopped. The v0.5.7 shutdown fix joined the worker pool too late: http.zig freed the per-connection read buffers (in websocket.deinit) before joining in-flight handlers, and a REQ filter holds zero-copy slices into those buffers, so a handler still matching events read freed memory. The pinned http.zig now joins the worker pool before any connection buffers are freed. Completes the v0.5.7 fix (#115, upstream PR karlseguin/http.zig#217)

## [0.5.8] - 2026-06-29

### Fixed

- Relay no longer crashes (SIGSEGV) during normal operation under connection churn. http.zig's epoll worker closed a finished connection's socket on a worker thread to drop it from epoll, then recycled the connection object later; that close raced epoll_wait, so the fd could stay armed past the recycle and a later event batch delivered a read for freed memory (getState on a null/recycled connection). The pinned http.zig now removes the fd from epoll and closes it on the loop thread before the connection is recycled. Pinned to a temporary privkeyio http.zig fork; upstream PR karlseguin/http.zig#216, will repoint once merged (#120)

## [0.5.7] - 2026-06-27

### Fixed

- Relay no longer crashes (SIGSEGV) on shutdown when a query result stream is still in flight. http.zig's non-blocking worker freed its thread-pool arena without joining handler threads, so a SIGTERM landing mid-query (e.g. during a backup) let the handler keep iterating the store while LMDB was torn down underneath it. The pinned http.zig now joins in-flight handlers before teardown (karlseguin/http.zig#215). LMDB meta-sync meant no data was at risk, but the unclean abort is gone (#115)

## [0.5.6] - 2026-06-25

### Fixed

- WebSocket upgrades rejected by the connection limiter now return HTTP 429 (per-IP cap) or 503 (global pool exhausted) instead of surfacing as an "unhandled exception" and HTTP 500. External monitors no longer report the relay DOWN when only the WS upgrade is rejected (NIP-11 `GET /` keeps returning 200). The rejected client's source IP is logged, sanitized against terminal-escape injection from a forged `X-Forwarded-For` (#116)

## [0.5.5] - 2026-06-21

### Changed

- Build against upstream `karlseguin/http.zig` and `karlseguin/websocket.zig` instead of the temporary privkeyio forks. All three fixes the forks carried (the TLS read-readiness poll, the websocket pin bump, and the recv/disown use-after-free worker fix) have merged upstream, so the pinned commits are byte-identical to the forks. No functional change from 0.5.4

## [0.5.4] - 2026-06-20

### Fixed

- Relay no longer crashes (SIGSEGV) a few hours into sustained inbound traffic. http.zig's epoll worker could process a `.signal` and a `.recv` for the same connection in one event batch; the signal freed the connection and the recv then dereferenced freed memory in `getState()`. The pinned http.zig fork now defers signal handling until the event batch is drained, so a freed connection is never touched. Confirmed in production: ran 13+ hours under load with no crash, versus crashing every ~3 hours before

## [0.5.3] - 2026-06-18

### Fixed

- Spider keeps `wss://` upstream connections open and streaming instead of cycling. The websocket read path was polling only the socket while `std.crypto.tls` held decrypted plaintext in its own buffer, so a poll could time out (returning a spurious "no data") while data was available in-process. The read now checks the TLS client's buffered length before polling, eliminating the reconnect churn (one upstream connection now streams thousands of events without reconnecting)

## [0.5.2] - 2026-06-18

### Fixed

- Spider no longer panics (debug builds) or churns through reconnects (release builds) on `wss://` upstream relays. The websocket client now polls for read readiness instead of using `SO_RCVTIMEO`, which on TLS connections surfaced a socket `EAGAIN` that crashed in debug and tore down connections in release. Upstream connections now stay open across quiet periods

## [0.5.1] - 2026-06-17

### Fixed

- Spider no longer escalates productive but short-lived upstream connections into multi-hour blackouts: a connection that synced events now resets the reconnect backoff regardless of how long it lasted. Max reconnect backoff capped at 5 minutes and the blackout at 30 minutes (was 1 hour / 24 hours)

## [0.5.0] - 2026-06-14

### Changed

- Default storage `sync` mode is now `meta` (durable, never corrupts) instead of `none`; use `sync = none` for maximum throughput on disposable data
- Updated libnostr-z to v0.3.6

### Fixed

- Fixed lost WebSocket read events under load that could leak connections (CLOSE_WAIT) and hang clients, e.g. an authed publish whose NIP-42 challenge arrived in the same packet as the upgrade response (http.zig and libnostr-z websocket fixes)
- No longer send `CLOSED` in reply to a client `CLOSE` (NIP-01)
- Fixed config file argument parsing and inline comment handling
- Fixed spider connection handling

## [0.1.2] - 2025-12-15

### Changed

- Updated libnostr-z to v0.1.5 with macOS ARM64 fix

## [0.1.1] - 2025-12-15

### Added

- NIP-13 proof of work support
- NIP-65 relay list metadata support
- NIP-70 protected events support

### Changed

- Updated libnostr-z to v0.1.4

## [0.1.0] - 2025-12-14

### Added

- Initial release of wisp nostr relay
- Core relay functionality with websocket support
- LMDB storage backend
- Spider mode for syncing events from external relays
- NIP-1 basic protocol support
- NIP-9 event deletion
- NIP-11 relay information document
- NIP-16 event treatment
- NIP-33 parameterized replaceable events
- NIP-40 expiration timestamp
- NIP-42 authentication
- NIP-45 COUNT support
- NIP-50 search capability
- NIP-77 negentropy sync
- Rate limiting and event validation
- Tag-based query filtering
- Import/export to JSONL format
- Configuration via TOML file or environment variables

[Unreleased]: https://github.com/privkeyio/wisp/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/privkeyio/wisp/compare/v0.5.15...v0.6.0
[0.5.15]: https://github.com/privkeyio/wisp/compare/v0.5.14...v0.5.15
[0.5.14]: https://github.com/privkeyio/wisp/compare/v0.5.13...v0.5.14
[0.5.13]: https://github.com/privkeyio/wisp/compare/v0.5.12...v0.5.13
[0.5.12]: https://github.com/privkeyio/wisp/compare/v0.5.11...v0.5.12
[0.5.11]: https://github.com/privkeyio/wisp/compare/v0.5.10...v0.5.11
[0.5.10]: https://github.com/privkeyio/wisp/compare/v0.5.9...v0.5.10
[0.5.9]: https://github.com/privkeyio/wisp/compare/v0.5.8...v0.5.9
[0.5.8]: https://github.com/privkeyio/wisp/compare/v0.5.7...v0.5.8
[0.5.7]: https://github.com/privkeyio/wisp/compare/v0.5.6...v0.5.7
[0.5.6]: https://github.com/privkeyio/wisp/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/privkeyio/wisp/compare/v0.5.4...v0.5.5
[0.5.4]: https://github.com/privkeyio/wisp/compare/v0.5.3...v0.5.4
[0.5.3]: https://github.com/privkeyio/wisp/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/privkeyio/wisp/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/privkeyio/wisp/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/privkeyio/wisp/compare/v0.1.2...v0.5.0
[0.1.2]: https://github.com/privkeyio/wisp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/privkeyio/wisp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/privkeyio/wisp/releases/tag/v0.1.0
