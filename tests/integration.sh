#!/usr/bin/env bash
# Black-box relay protocol test. Publishes and queries events against a running
# wisp instance and asserts the responses, covering the NIPs wisp advertises.
#
# Usage: tests/integration.sh [relay-url]   (default ws://127.0.0.1:7777)
# Requires: noz (https://github.com/privkeyio/noz) on PATH.
#
# Exits non-zero if any assertion fails, so it can gate CI.
set -u
R="${1:-ws://127.0.0.1:7777}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001
SEC2=0000000000000000000000000000000000000000000000000000000000000002
PK1=$(noz key public $SEC1)
PK2=$(noz key public $SEC2)
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
req() { timeout 10 noz req "$@" "$R" 2>/dev/null | grep -c '"kind"'; }
pub() { noz event "$@" "$R" >/dev/null 2>&1; }
idof() { noz event "$@" "$R" 2>/dev/null | grep -oE '"id":"[a-f0-9]{64}"' | head -1 | cut -d'"' -f4; }

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

# --- Tag index: a non-maximal binary tag must not leak the lexicographic-max event ---
# #e (0x65) sorts below the #p (0x70) entries already stored. Before the tag-index
# seek/prefix fix, a bare #e query returned the max-key (#p) event regardless of the
# queried value; assert exact matches and a clean empty result for an unknown value.
EREF=00000000000000000000000000000000000000000000000000000000deadbeef
pub --sec $SEC1 -k 1 -e "$EREF" -c "references deadbeef"
sleep 0.5
chk "tag index #e returns only matching events" 1 "$(req -e "$EREF")"
chk "tag index #e unknown value is empty" 0 \
  "$(req -e 00000000000000000000000000000000000000000000000000000000feedface)"

# --- NIP-09 deletion ---
DID=$(idof --sec $SEC1 -c "delete me")
sleep 0.5
chk "NIP-09 event present before delete" 1 "$(req -i "$DID")"
pub --sec $SEC1 -k 5 -e "$DID" -c ""
sleep 0.8
chk "NIP-09 event gone after delete" 0 "$(req -i "$DID")"

# --- NIP-16 replaceable (kind 0), latest wins ---
rbase=$(($(date +%s) - 20))
pub --sec $SEC2 -k 0 --ts $rbase -c '{"name":"v1"}'
pub --sec $SEC2 -k 0 --ts $((rbase + 1)) -c '{"name":"v2"}'
sleep 0.5
chk "NIP-16 replaceable kept single" 1 "$(req -k 0 -a "$PK2")"
chk "NIP-16 replaceable keeps latest" "v2" \
  "$(timeout 10 noz req -k 0 -a "$PK2" "$R" 2>/dev/null | grep -o 'v[12]' | head -1)"

# --- NIP-16 ephemeral (kind 20000) not stored ---
pub --sec $SEC1 -k 20000 -c "ephemeral"
sleep 0.5
chk "NIP-16 ephemeral not stored" 0 "$(req -k 20000)"

# --- NIP-16 ephemeral is RELAYED LIVE to an open subscription (broadcast, not persisted) ---
# Regression for the fix that lets ephemerals (20000-29999) reach subscribers despite not being
# stored -- required by clients that coordinate over ephemeral events (e.g. keep's FROST/OPRF, kind
# 24242). Subscribe first, publish while subscribed, and assert the subscriber received it.
EPHOUT=$(mktemp)
timeout 4 noz req -k 20001 "$R" >"$EPHOUT" 2>/dev/null &
EPHPID=$!
sleep 1
pub --sec $SEC1 -k 20001 -c "live-ephemeral"
wait $EPHPID
chk "NIP-16 ephemeral delivered live to open subscription" 1 "$(grep -c '"kind"' "$EPHOUT")"
chk "NIP-16 ephemeral still not stored after live delivery" 0 "$(req -k 20001)"
rm -f "$EPHOUT"

# --- NIP-33 addressable (kind 30023 + d tag) ---
abase=$(($(date +%s) - 20))
pub --sec $SEC2 -k 30023 -d slugA --ts $abase -c "A-v1"
pub --sec $SEC2 -k 30023 -d slugA --ts $((abase + 1)) -c "A-v2"
pub --sec $SEC2 -k 30023 -d slugB --ts $((abase + 1)) -c "B"
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

# --- NIP-45 COUNT (noz prints the count to stdout) ---
chk "NIP-45 COUNT returns a count" 1 \
  "$(timeout 10 noz count -k 1 -t t=wisptag "$R" 2>/dev/null)"

# --- NIP-11 relay information document ---
INFO=$(timeout 10 noz relay "$R" 2>/dev/null)
present() { echo "$INFO" | grep -qE "\"$1\"[[:space:]]*:" && echo 1 || echo 0; }
chk "NIP-11 info has name" 1 "$(present name)"
chk "NIP-11 info has software" 1 "$(present software)"
chk "NIP-11 info has supported_nips" 1 "$(present supported_nips)"

# --- Browser interop: NIP-11 content-type + CORS headers ---
HTTP="${R/ws:/http:}"
HTTP="${HTTP/wss:/https:}"
hdrs=$(curl -s -i -H "Accept: application/nostr+json" "$HTTP/" 2>/dev/null)
chk "NIP-11 served as application/nostr+json" 1 \
  "$(echo "$hdrs" | grep -ci 'content-type:[[:space:]]*application/nostr+json')"
chk "NIP-11 sends CORS allow-origin" 1 \
  "$(echo "$hdrs" | grep -ci 'access-control-allow-origin:[[:space:]]*\*')"
chk "CORS preflight (OPTIONS) answered" 1 \
  "$(curl -s -i -X OPTIONS "$HTTP/" 2>/dev/null | grep -qi 'access-control-allow-methods' && echo 1 || echo 0)"

# --- NIP-01 limit: returns the newest N events, newest first ---
# Explicit, distinct created_at values so ordering is deterministic (no
# second-granularity ties that would otherwise break by event id).
SEC3=0000000000000000000000000000000000000000000000000000000000000003
PK3=$(noz key public $SEC3)
base=$(($(date +%s) - 10))
pub --sec $SEC3 --ts $base -c "lim1"
pub --sec $SEC3 --ts $((base + 1)) -c "lim2"
pub --sec $SEC3 --ts $((base + 2)) -c "lim3"
sleep 0.3
chk "NIP-01 limit caps to N" 2 "$(req -k 1 -a "$PK3" -l 2)"
chk "NIP-01 limit returns newest first" "lim3" \
  "$(timeout 10 noz req -k 1 -a "$PK3" -l 2 "$R" 2>/dev/null | grep -o 'lim[0-9]' | head -1)"

# --- NIP-40 expiration: expired rejected at publish, future-expiry kept ---
now=$(date +%s)
pub --sec $SEC1 -c "exp40past" -t expiration=$((now - 100))
sleep 0.3
chk "NIP-40 expired event not stored" 0 "$(req -k 1 --search exp40past -a "$PK1")"
pub --sec $SEC1 -c "exp40future" -t expiration=$((now + 3600))
sleep 0.3
chk "NIP-40 future-expiry event stored" 1 "$(req -k 1 --search exp40future -a "$PK1")"

# --- NIP-40 serve-time expiry: a stored event is no longer served once expired ---
pub --sec $SEC1 -c "exp40soon" -t expiration=$((now + 2))
sleep 0.3
chk "NIP-40 not-yet-expired is served" 1 "$(req -k 1 --search exp40soon -a "$PK1")"
sleep 3
chk "NIP-40 expired-after-storage is hidden" 0 "$(req -k 1 --search exp40soon -a "$PK1")"

# --- created_at upper limit (NIP-11 limitation): far-future rejected ---
pub --sec $SEC1 --ts $((now + 100000)) -c "tslimitfuture"
sleep 0.3
chk "created_at far-future event rejected" 0 "$(req -k 1 --search tslimitfuture -a "$PK1")"

# --- NIP-70 protected events: rejected by default (no auth available) ---
prot=$(noz event --sec $SEC1 -t '-' -c protected70 "$R" 2>&1 | grep -q success && echo ok || echo reject)
chk "NIP-70 protected event rejected without auth" reject "$prot"
sleep 0.3
chk "NIP-70 protected event not stored" 0 "$(req -k 1 --search protected70 -a "$PK1")"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
