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
    bash tests/integration_negentropy_truncation.sh ws://127.0.0.1:7789 # NIP-77 scan-cap NEG-ERR
    bash tests/integration_spider.sh ws://A ws://B             # spider NIP-77 client
    bash tests/integration_spider_shutdown.sh ./zig-out/bin/wisp # SIGTERM during spider bootstrap
    bash tests/integration_concurrency.sh ws://127.0.0.1:7777  # many concurrent conns
    bash tests/integration_ws_idle_reclaim.sh ws://127.0.0.1:7777 # idle-close slot/bucket reclaim

    bash tests/integration_ws_rate_limit.sh ws://127.0.0.1:7777   # per-IP token buckets
    bash tests/integration_handover_leak.sh ws://127.0.0.1:7777 PID # handover slot/fd leak

The idle-reclaim test needs a dedicated relay (no other WebSocket clients)
started with a short idle window and a per-IP limit of 2, e.g.
`WISP_IDLE_SECONDS=1 WISP_MAX_CONNECTIONS_PER_IP=2`.

The handover-leak test is Linux-only: it counts the relay's own socket
descriptors and CPU time under `/proc`, so it takes the relay's **pid as a
second argument** and exits immediately without one. It needs a dedicated relay
started with `WISP_WORKERS=1` (so every connection shares one handover list) and
a per-IP limit far above its concurrency, e.g.
`WISP_MAX_CONNECTIONS_PER_IP=100000`. With a low limit the connections are
rejected before they ever reach a handover and the test proves nothing.

The scan-cap truncation test needs a dedicated relay started with `WISP_NEGENTROPY_MAX_SYNC_EVENTS=2 WISP_QUERY_SCAN_MULTIPLIER=1`, so that one old match sits beyond the scan cap of the events the test publishes.

The spider shutdown test starts its own processes, so it takes the **wisp binary** instead of a URL: a stand-in upstream (python3) that accepts the bootstrap REQ and never answers it, and a spider relay pointed at it. It asserts the relay listens while the bootstrap is in flight and exits within 6s of SIGTERM. It uses ports 7790 and 7791 (override with `SPIDER_PORT` and `UPSTREAM_PORT`).

These mirror the jobs in `.github/workflows/ci.yml`.
