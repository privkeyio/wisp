#!/usr/bin/env bash
# NIP-77 negentropy sync test. Seeds relay A, then uses negentropy
# reconciliation (via `noz sync`) to replicate its events into empty relay B,
# and asserts B received them.
#
# Usage: tests/integration_negentropy.sh <relay-a-url> <relay-b-url>
# Requires: noz on PATH. Exits non-zero if any assertion fails.
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
count() { timeout 10 noz req -k 1 -l 100 "$1" 2>/dev/null | grep -c '"kind"'; }

# distinct created_at values so every event is unique
for i in $(seq 1 $N); do
  timeout 6 noz event --sec $SEC1 --ts $((1700000000 + i)) -c "neg$i" "$A" >/dev/null 2>&1
done
sleep 1

chk "relay A seeded" "$N" "$(count "$A")"
chk "relay B empty before sync" 0 "$(count "$B")"

# noz sync drains the source fully before publishing, so a single pass copies
# A's complete set into B (re-running is idempotent; the relay dedupes).
timeout 40 noz sync "$A" "$B" -k 1 >/dev/null 2>&1
sleep 1
got="$(count "$B")"

chk "NIP-77 negentropy replicated A into B" "$N" "$got"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
