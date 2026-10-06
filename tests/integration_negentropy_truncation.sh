#!/usr/bin/env bash
# NIP-77 scan-cap truncation test: when the serving side's capped query stops
# scanning before it has seen every match, NEG-OPEN must answer NEG-ERR rather
# than seal the partial set. A sealed partial set makes reconciliation report
# events as missing that the relay actually holds.
#
# The relay must run with WISP_NEGENTROPY_MAX_SYNC_EVENTS=2 and
# WISP_QUERY_SCAN_MULTIPLIER=1, so enumeration asks for 3 events and may scan
# at most 3 index entries. One old match sits behind four newer non-matching
# events, so the scan hits the cap with the match still unseen.
#
# Usage: tests/integration_negentropy_truncation.sh <relay-ws-url>
# Requires: noz on PATH. Exits non-zero if any assertion fails.
set -u
R="${1:?relay url required}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001
SEC2=0000000000000000000000000000000000000000000000000000000000000002
PK1=$(noz key public $SEC1)
# Never published: a second author keeps the filter off the single-author index,
# forcing the newest-first scan of every event.
PK_NONE=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

pass=0
fail=0
chk() { # desc expected-substring actual
  case "$3" in
    *"$2"*) echo "ok   - $1"; pass=$((pass + 1)) ;;
    *) echo "FAIL - $1 (expected '$2', got '$3')"; fail=$((fail + 1)) ;;
  esac
}
neg_open() { # sub_id filter-json
  timeout 8 noz send "$R" "[\"NEG-OPEN\",\"$1\",$2,\"61\"]" 2>/dev/null
}

# Relative timestamps: fixed ones would age past max_event_age and stop storing.
base=$(($(date +%s) - 1000))
timeout 6 noz event --sec $SEC1 --ts "$base" -c "old match" "$R" >/dev/null 2>&1
for i in 1 2 3 4; do
  timeout 6 noz event --sec $SEC2 --ts $((base + 10 + i)) -c "newer $i" "$R" >/dev/null 2>&1
done
sleep 1

# Control: the same match set through the single-author index scans only the
# match, so it is under both caps and reconciles. This is what makes the NEG-ERR
# below a scan-cap truncation and not an oversized match set.
chk "match set under the caps reconciles" '["NEG-MSG","ctl",' \
  "$(neg_open ctl "{\"kinds\":[1],\"authors\":[\"$PK1\"]}")"

chk "scan stopped by the cap before the match is NEG-ERR, not a sealed partial set" \
  '["NEG-ERR","trunc","error: result set too large to reconcile"]' \
  "$(neg_open trunc "{\"kinds\":[1],\"authors\":[\"$PK1\",\"$PK_NONE\"]}")"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
