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
    bash tests/integration_ws_idle_reclaim.sh ws://127.0.0.1:7777 # idle-close slot/bucket reclaim

The idle-reclaim test needs a dedicated relay (no other WebSocket clients)
started with a short idle window and a per-IP limit of 2, e.g.
`WISP_IDLE_SECONDS=1 WISP_MAX_CONNECTIONS_PER_IP=2`.

These mirror the jobs in `.github/workflows/ci.yml`.
