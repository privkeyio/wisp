# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/privkeyio/wisp/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/privkeyio/wisp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/privkeyio/wisp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/privkeyio/wisp/releases/tag/v0.1.0
