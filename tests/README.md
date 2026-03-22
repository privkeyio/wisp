# wisp testing docs

Tests should be run from the *root* of the project.

## Prerequisites

- [nostril](https://github.com/jb55/nostril) - tool for creating nostr events

Build nostril:

    git clone https://github.com/jb55/nostril /tmp/nostril
    cd /tmp/nostril && make
    cp /tmp/nostril/nostril test/

## Tests for event writing, including replacements, deletions, etc:

    perl test/writeTest.pl

## Fuzz tests

Note that these tests need a well populated DB. For best coverage, use the [wellordered 500k](https://wiki.wellorder.net/wiki/nostr-datasets/) data-set:

    zstdcat ../nostr-dumps/nostr-wellorder-early-500k-v1.jsonl.zst | ./zig-out/bin/wisp import --db wisp-db-test/wisp.db

If successful, these tests will run forever, so you can run them overnight to see if any errors occur.

The tests are deterministic, but you can change the seed by setting the `SEED` env variable.

These commands test the query engine, with and without `limit`:

    perl test/filterFuzzTest.pl scan-limit
    perl test/filterFuzzTest.pl scan
