# Benchmarks

Peak write throughput, all relays at 100% delivery:

| Relay | Events/sec | p99 Latency | Memory (RSS) |
|-------|-----------:|------------:|-------------:|
| **Wisp** | **25,600** | **0.28 ms** | 11 MB |
| nostr-rs-relay | 5,400 | 5.9 ms | 20 MB |
| strfry | 2,800 | 2.9 ms | 3 MB |

Measured with [nostr-bench](https://github.com/privkeyio/nostr-bench): 5,000 events x 4
workers at peak rate (`--rate 0`), native release builds on a 16-core Linux host, with the
event-rate limit raised. `RssAnon` sampled during the run; figures are representative of three
stable iterations.

This is peak write capability with Wisp in `sync = none` (non-durable). Wisp's **default is
`sync = meta`** (durable, never corrupts), which trades raw throughput for crash safety; in
the durable modes throughput scales with publisher concurrency because writes are
group-committed (see [Configuration](configuration.md#durability)). strfry and nostr-rs-relay
write durably by default, so a fair durable-vs-durable comparison runs Wisp in `meta`/`full`.
On throughput and p99 latency Wisp leads; strfry stays smallest in memory.
