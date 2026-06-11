#!/usr/bin/env bash
# NIP-77 negentropy sync test. Seeds relay A, then uses negentropy
# reconciliation (via `nak sync`) to replicate its events into empty relay B,
# and asserts B received them.
#
# Usage: tests/integration_negentropy.sh <relay-a-url> <relay-b-url>
# Requires: nak on PATH. Exits non-zero if any assertion fails.
set -u
A="${1:?relay A url required}"
B="${2:?relay B url required}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001
N=8
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
count() { timeout 10 nak req -k 1 -l 100 "$1" 2>/dev/null | grep -c '"kind"'; }

# distinct created_at values so every event is unique
for i in $(seq 1 $N); do
  timeout 6 nak event --sec $SEC1 --ts $((1700000000 + i)) -c "neg$i" "$A" >/dev/null 2>&1
done
sleep 1

chk "relay A seeded" "$N" "$(count "$A")"
chk "relay B empty before sync" 0 "$(count "$B")"

timeout 40 nak sync "$A" "$B" -k 1 >/dev/null 2>&1
sleep 1

chk "NIP-77 negentropy replicated A into B" "$N" "$(count "$B")"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
