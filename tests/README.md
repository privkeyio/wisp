# wisp testing docs

Run all commands from the *root* of the project.

## Unit tests

Inline Zig tests for parsing, filtering, rate limiting, NIP-86 dispatch, and the
metrics endpoint:

    zig build test

LMDB binding smoke test:

    zig build test-lmdb

## Integration tests

Shell scripts that exercise a running relay over the wire. Each takes the
relay's URL (start a relay first, e.g. `./zig-out/bin/wisp`):

    bash tests/integration.sh ws://127.0.0.1:7777              # protocol, NIPs, CORS
    bash tests/integration_restrict.sh ws://127.0.0.1:7777     # auth / protected / PoW
    bash tests/integration_management.sh http://127.0.0.1:7777 # NIP-86 + IP block
    bash tests/integration_negentropy.sh ws://A ws://B         # NIP-77 relay sync
    bash tests/integration_spider.sh ws://A ws://B             # spider NIP-77 client
    bash tests/integration_concurrency.sh ws://127.0.0.1:7777  # many concurrent conns

These mirror the jobs in `.github/workflows/ci.yml`.
