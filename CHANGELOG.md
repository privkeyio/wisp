# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Updated libnostr-z to v0.1.6

### Fixed

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
