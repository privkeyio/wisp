# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
