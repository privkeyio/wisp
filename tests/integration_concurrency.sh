#!/usr/bin/env bash
# Concurrency smoke test: hammer the relay with many concurrent connections and
# assert it stays alive and responsive afterward. Guards against races,
# deadlocks, and crashes under load (it does not assert throughput).
#
# Usage: tests/integration_concurrency.sh <relay-ws-url>
# Requires: nak on PATH. Exits non-zero if any assertion fails.
set -u
R="${1:?relay url required}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001
N=200
pass=0
fail=0

chk() { # desc expected actual
  if [ "$2" = "$3" ]; then
    echo "ok   - $1"
    pass=$((pass + 1))
  else
    echo "FAIL - $1 (expected '$2', got '$3')"
    fail=$((fail + 1))
  fi
}

# Burst: N concurrent publishers and N concurrent subscribers.
seq 1 $N | xargs -P 50 -I{} timeout 10 \
  nak event --sec $SEC1 -c "concurrent{}" "$R" >/dev/null 2>&1
seq 1 $N | xargs -P 50 -I{} timeout 10 \
  nak req -k 1 -l 1 "$R" >/dev/null 2>&1
sleep 1

# The relay must still answer NIP-11 (process alive, accept loop healthy).
chk "relay responsive after $N concurrent connections" 1 \
  "$(timeout 10 nak relay "$R" 2>/dev/null | grep -c '"name"')"

# ...and still function: publish then read back.
id=$(timeout 10 nak event --sec $SEC1 -c "post-stress" "$R" 2>/dev/null \
  | grep -oE '"id":"[a-f0-9]{64}"' | head -1 | cut -d'"' -f4)
if [ -z "$id" ]; then
  echo "FAIL - relay did not accept an event after load"
  echo "1 passed, 1 failed"
  exit 1
fi
sleep 0.5
chk "relay still serves REQ after load" 1 \
  "$(timeout 10 nak req -i "$id" "$R" 2>/dev/null | grep -c '"kind"')"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
