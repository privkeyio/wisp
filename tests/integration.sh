#!/usr/bin/env bash
# Black-box relay protocol test. Publishes and queries events against a running
# wisp instance and asserts the responses, covering the NIPs wisp advertises.
#
# Usage: tests/integration.sh [relay-url]   (default ws://127.0.0.1:7777)
# Requires: nak (https://github.com/fiatjaf/nak) on PATH.
#
# Exits non-zero if any assertion fails, so it can gate CI.
set -u
R="${1:-ws://127.0.0.1:7777}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001
SEC2=0000000000000000000000000000000000000000000000000000000000000002
PK1=$(nak key public $SEC1)
PK2=$(nak key public $SEC2)
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
# count events returned by a REQ
req() { timeout 10 nak req "$@" "$R" 2>/dev/null | grep -c '"kind"'; }
pub() { nak event "$@" "$R" >/dev/null 2>&1; }
idof() { nak event "$@" "$R" 2>/dev/null | grep -oE '"id":"[a-f0-9]{64}"' | head -1 | cut -d'"' -f4; }

# --- NIP-01: publish + EVENT delivery on REQ (the core round-trip) ---
ID=$(idof --sec $SEC1 -c "hello world")
sleep 0.5
chk "NIP-01 REQ by id returns the event" 1 "$(req -i "$ID")"
chk "NIP-01 REQ by author" 1 "$(req -a "$PK1")"
chk "NIP-01 REQ by kind" 1 "$(req -k 1 -a "$PK1")"
chk "NIP-01 REQ wrong kind is empty" 0 "$(req -k 9999 -a "$PK1")"
chk "NIP-01 since in future is empty" 0 "$(req -k 1 -s 9999999999)"
chk "NIP-01 until in past is empty" 0 "$(req -k 1 -u 1)"

# --- NIP-01 tag filter ---
pub --sec $SEC1 -k 1 -t t=wisptag -c "tagged"
sleep 0.5
chk "NIP-01 #t tag filter" 1 "$(req -k 1 -t t=wisptag)"

# --- NIP-09 deletion ---
DID=$(idof --sec $SEC1 -c "delete me")
sleep 0.5
chk "NIP-09 event present before delete" 1 "$(req -i "$DID")"
pub --sec $SEC1 -k 5 -e "$DID" -c ""
sleep 0.8
chk "NIP-09 event gone after delete" 0 "$(req -i "$DID")"

# --- NIP-16 replaceable (kind 0), latest wins ---
pub --sec $SEC2 -k 0 -c '{"name":"v1"}'
sleep 1.2
pub --sec $SEC2 -k 0 -c '{"name":"v2"}'
sleep 0.5
chk "NIP-16 replaceable kept single" 1 "$(req -k 0 -a "$PK2")"
chk "NIP-16 replaceable keeps latest" "v2" \
  "$(timeout 10 nak req -k 0 -a "$PK2" "$R" 2>/dev/null | grep -o 'v[12]' | head -1)"

# --- NIP-16 ephemeral (kind 20000) not stored ---
pub --sec $SEC1 -k 20000 -c "ephemeral"
sleep 0.5
chk "NIP-16 ephemeral not stored" 0 "$(req -k 20000)"

# --- NIP-33 addressable (kind 30023 + d tag) ---
pub --sec $SEC2 -k 30023 -d slugA -c "A-v1"
sleep 1.2
pub --sec $SEC2 -k 30023 -d slugA -c "A-v2"
sleep 0.5
pub --sec $SEC2 -k 30023 -d slugB -c "B"
sleep 0.5
chk "NIP-33 same d-tag replaced" 1 "$(req -k 30023 -d slugA)"
chk "NIP-33 different d-tags kept" 2 "$(req -k 30023 -a "$PK2")"

# --- NIP-50 search filters by content ---
pub --sec $SEC1 -c "anchovy pizza margherita"
pub --sec $SEC1 -c "caesar salad bowl"
sleep 0.5
chk "NIP-50 search matches content" 1 "$(req -k 1 --search anchovy -a "$PK1")"
chk "NIP-50 search excludes non-matches" 0 "$(req -k 1 --search zzznotfound -a "$PK1")"
# search via the kind index (no author): the kind fast-path must not skip content match
chk "NIP-50 search via kind index" 1 "$(req -k 1 --search anchovy)"
# search routed through the tag index (#p binary value): content match still applies,
# filtering to one of two events that share the tag
pub --sec $SEC1 -k 1 -p "$PK2" -c "tuna sandwich"
pub --sec $SEC1 -k 1 -p "$PK2" -c "veggie wrap"
sleep 0.5
chk "NIP-50 search via tag index" 1 "$(req -k 1 -p "$PK2" --search tuna)"

# --- NIP-45 COUNT (nak writes "<relay>: <n>" to stderr) ---
chk "NIP-45 COUNT returns a count" 1 \
  "$(timeout 10 nak count -k 1 -t t=wisptag "$R" 2>&1 | awk '/: [0-9]+$/{print $NF}')"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
