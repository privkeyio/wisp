#!/usr/bin/env bash
# NIP-77 boundary test: a match set of EXACTLY negentropy_max_sync_events must
# reconcile, not be rejected.
#
# The serving side enumerates through the capped query(). If it asks for exactly
# the cap, the iterator stops once it has returned that many events, so a
# complete set of exactly the cap is indistinguishable from one that exceeds it,
# and the relay answers NEG-ERR "blocked: too many events" for a set it could
# have served. Asking for one more event is what separates the two cases.
#
# Both relays must run with WISP_NEGENTROPY_MAX_SYNC_EVENTS set to <cap>.
#
# Usage: tests/integration_negentropy_boundary.sh <relay-a-url> <relay-b-url> <cap>
# Requires: noz on PATH. Exits non-zero if any assertion fails.
set -u
A="${1:?relay A url required}"
B="${2:?relay B url required}"
CAP="${3:?cap required}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001

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
count() { timeout 10 noz req -k 1 -l $((CAP * 4)) "$1" 2>/dev/null | grep -c '"kind"'; }

# Exactly CAP events, distinct created_at so each is unique. Not one under, not
# one over: the boundary is the whole point.
for i in $(seq 1 "$CAP"); do
  timeout 6 noz event --sec $SEC1 --ts $((1700000000 + i)) -c "bound$i" "$A" >/dev/null 2>&1
done
sleep 1

chk "relay A holds exactly the cap" "$CAP" "$(count "$A")"
chk "relay B empty before sync" 0 "$(count "$B")"

# The client does not surface the relay's NEG-ERR text, so asserting on the
# message would pass whether or not the bug is present. What the bug actually
# does is prevent replication, so that is what is asserted: with the off-by-one
# the relay answers NEG-ERR, nothing reconciles, and B ends up empty.
timeout 40 noz sync "$A" "$B" -k 1 >/dev/null 2>&1
sleep 1

chk "set of exactly the cap reconciled into B" "$CAP" "$(count "$B")"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
