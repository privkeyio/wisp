#!/usr/bin/env bash
# Spider mode test (NIP-77 client sync). Seeds the SOURCE relay with an admin
# contact list (kind 3) following another pubkey, plus that pubkey's notes, then
# verifies a spider-configured relay pulls them.
#
# The SPIDER relay must already be running with:
#   WISP_SPIDER_ENABLED=true
#   WISP_SPIDER_ADMIN=<SEC1 pubkey, below>
#   WISP_SPIDER_RELAYS=<source ws url>
#
# Usage: tests/integration_spider.sh <source-ws-url> <spider-ws-url>
# Requires: noz on PATH. Exits non-zero if any assertion fails.
set -u
SRC="${1:?source relay url required}"
SPD="${2:?spider relay url required}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001
SEC2=0000000000000000000000000000000000000000000000000000000000000002
PK2=$(noz key public $SEC2)
N=5
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
count() { timeout 8 noz req -k 1 -a "$PK2" -l 50 "$1" 2>/dev/null | grep -c '"kind"'; }

# Admin (SEC1) follows SEC2 via a kind-3 contact list; SEC2 publishes notes.
noz event --sec $SEC1 -k 3 -p "$PK2" -c "" "$SRC" >/dev/null 2>&1
for i in $(seq 1 $N); do
  noz event --sec $SEC2 -c "spider note $i" "$SRC" >/dev/null 2>&1
done
sleep 1
chk "source relay seeded with followed-author notes" "$N" "$(count "$SRC")"

# The spider re-bootstraps its contact list on each sync interval, so it picks
# up the seed even though it started first. Give it a few intervals.
synced=0
start=$SECONDS
until [ $((SECONDS - start)) -ge 45 ]; do
  sleep 3
  synced=$(count "$SPD")
  [ "$synced" -ge "$N" ] && break
done
chk "spider synced followed-author notes via NIP-77" "$N" "$synced"

# Live sync: a new note on the source should reach the spider.
noz event --sec $SEC2 -c "spider live note" "$SRC" >/dev/null 2>&1
live=0
start=$SECONDS
until [ $((SECONDS - start)) -ge 30 ]; do
  sleep 3
  live=$(count "$SPD")
  [ "$live" -ge $((N + 1)) ] && break
done
chk "spider received live note via subscription" $((N + 1)) "$live"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
