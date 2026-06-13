# Benchmarks

Peak write throughput, all relays at 100% delivery:

| Relay | Events/sec | p99 Latency | Memory (RSS) |
|-------|-----------:|------------:|-------------:|
| **Wisp** | **25,600** | **0.28 ms** | 11 MB |
| nostr-rs-relay | 5,400 | 5.9 ms | 20 MB |
| strfry | 2,800 | 2.9 ms | 3 MB |

Measured with [nostr-bench](https://github.com/privkeyio/nostr-bench): 5,000 events x 4
workers at peak rate (`--rate 0`), native release builds on a 16-core Linux host, default
configs with the event-rate limit raised. `RssAnon` sampled during the run; figures are
representative of three stable iterations.

Wisp leads on throughput (~9x strfry, ~5x nostr-rs-relay) and p99 latency; strfry stays
smallest in memory. Wisp defaults to LMDB `MDB_NOSYNC` (fast, less crash-durable) while
strfry writes durably, so part of the write-throughput gap reflects that tradeoff.
