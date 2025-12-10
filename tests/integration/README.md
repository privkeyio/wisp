# Integration Tests

## Requirements

- `nak` - Nostr CLI tool: https://github.com/fiatjaf/nak
- `python3` with `websocket-client` package (for NIP-45 COUNT tests)

## Running Tests

```bash
NAK_BIN=/path/to/nak ./tests/integration/run_tests.sh
```

Or if `nak` is in your PATH:

```bash
./tests/integration/run_tests.sh
```

## Test Coverage

- **NIP-01**: Basic protocol (publish, query, filters)
- **NIP-09**: Event deletion
- **NIP-11**: Relay information document
- **NIP-45**: COUNT support
- **Filters**: ID, author, kind, tag filtering
- **Replaceable**: Kind 0, 3, 10000-19999, 30000-39999
- **Limits**: Future events, content size, validation
- **CLI**: Import/export commands
