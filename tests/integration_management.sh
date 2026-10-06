#!/usr/bin/env bash
# NIP-86 relay management API test. The relay must be running with
# WISP_ADMIN_PUBKEYS set to SEC1's pubkey (below) and WISP_RELAY_URL set to the
# same <http-url> passed here (NIP-98 auth checks the URL).
#
# Usage: tests/integration_management.sh <http-url>   e.g. http://127.0.0.1:7781
# Requires: noz, curl, sha256sum on PATH. Exits non-zero if any assertion fails.
set -u
HTTP="${1:?http url required}"
WS="${HTTP/http:/ws:}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001
SEC2=0000000000000000000000000000000000000000000000000000000000000002
SEC3=0000000000000000000000000000000000000000000000000000000000000003
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
has() { case "$1" in *"$2"*) echo 1 ;; *) echo 0 ;; esac; }
published() { timeout 10 noz event --sec "$1" -c "$2" "$WS" 2>&1 | grep -c success; }

# A NIP-86 call authorized with a NIP-98 (kind 27235) event signed by <sec>,
# including the required payload (sha256 of the body) tag.
call() { # sec body
  local sec=$1 body=$2 payload ev b64
  payload=$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)
  ev=$(timeout 10 noz event --sec "$sec" -k 27235 -t u="$HTTP" -t method=POST -t payload="$payload" -c "" 2>/dev/null)
  b64=$(printf '%s' "$ev" | base64 -w0)
  curl -s --connect-timeout 5 --max-time 10 -X POST -H "Content-Type: application/nostr+json+rpc" \
    -H "Authorization: Nostr $b64" -d "$body" "$HTTP"
}

chk "NIP-86 admin lists supported methods" 1 \
  "$(has "$(call $SEC1 '{"method":"supportedmethods","params":[]}')" 'banpubkey')"
chk "NIP-86 non-admin is forbidden" 1 \
  "$(has "$(call $SEC2 '{"method":"supportedmethods","params":[]}')" 'forbidden')"

chk "pubkey can publish before ban" 1 "$(published $SEC2 'before ban')"
call $SEC1 "{\"method\":\"banpubkey\",\"params\":[\"$PK2\",\"abuse\"]}" >/dev/null
chk "NIP-86 banpubkey persisted" 1 \
  "$(has "$(call $SEC1 '{"method":"listbannedpubkeys","params":[]}')" "$PK2")"
chk "banned pubkey is blocked from publishing" 0 "$(published $SEC2 'after ban')"

call $SEC1 "{\"method\":\"unbanpubkey\",\"params\":[\"$PK2\"]}" >/dev/null
chk "NIP-86 unbanpubkey lifts the ban" 1 "$(published $SEC2 'after unban')"

# ban and allow lists are mutually exclusive
call $SEC1 "{\"method\":\"banpubkey\",\"params\":[\"$PK2\"]}" >/dev/null
call $SEC1 "{\"method\":\"allowpubkey\",\"params\":[\"$PK2\"]}" >/dev/null
chk "NIP-86 allowpubkey removes the ban" 0 \
  "$(has "$(call $SEC1 '{"method":"listbannedpubkeys","params":[]}')" "$PK2")"
chk "pubkey outside the allowlist is blocked" 0 "$(published $SEC3 'not allowed')"
call $SEC1 "{\"method\":\"unallowpubkey\",\"params\":[\"$PK2\"]}" >/dev/null
chk "NIP-86 unallowpubkey empties the allowlist" 0 \
  "$(has "$(call $SEC1 '{"method":"listallowedpubkeys","params":[]}')" "$PK2")"
chk "empty allowlist admits everyone again" 1 "$(published $SEC3 'open again')"

EID=00000000000000000000000000000000000000000000000000000000000000ee
call $SEC1 "{\"method\":\"banevent\",\"params\":[\"$EID\"]}" >/dev/null
call $SEC1 "{\"method\":\"allowevent\",\"params\":[\"$EID\"]}" >/dev/null
chk "NIP-86 allowevent removes the event ban" 0 \
  "$(has "$(call $SEC1 '{"method":"listbannedevents","params":[]}')" "$EID")"
chk "NIP-86 listallowedevents" 1 \
  "$(has "$(call $SEC1 '{"method":"listallowedevents","params":[]}')" "$EID")"
call $SEC1 "{\"method\":\"unallowevent\",\"params\":[\"$EID\"]}" >/dev/null
chk "NIP-86 unallowevent" 0 \
  "$(has "$(call $SEC1 '{"method":"listallowedevents","params":[]}')" "$EID")"
call $SEC1 "{\"method\":\"banevent\",\"params\":[\"$EID\"]}" >/dev/null
call $SEC1 "{\"method\":\"unbanevent\",\"params\":[\"$EID\"]}" >/dev/null
chk "NIP-86 unbanevent" 0 \
  "$(has "$(call $SEC1 '{"method":"listbannedevents","params":[]}')" "$EID")"

# disallowkind blocks a kind even with no allowlist, and allowkind lifts it
kind7() { timeout 10 noz event --sec "$SEC3" -k 7 -c "$1" "$WS" 2>&1 | grep -c success; }
call $SEC1 '{"method":"disallowkind","params":[7]}' >/dev/null
chk "NIP-86 disallowkind blocks the kind" 0 "$(kind7 '+')"
chk "NIP-86 listdisallowedkinds" 1 \
  "$(has "$(call $SEC1 '{"method":"listdisallowedkinds","params":[]}')" '7')"
chk "other kinds still publish" 1 "$(published $SEC3 'kind 1 ok')"
call $SEC1 '{"method":"allowkind","params":[7]}' >/dev/null
chk "NIP-86 allowkind clears the disallow" '{"result":[]}' "$(call $SEC1 '{"method":"listdisallowedkinds","params":[]}')"
chk "allowed kind publishes" 1 "$(kind7 '++')"
chk "kind outside the allowlist is blocked" 0 "$(published $SEC3 'kind 1 now blocked')"

# allowevent approves one event past the kind allowlist
TS=1700000000
APPROVED=$(timeout 10 noz event --sec "$SEC3" --ts $TS -c approved 2>/dev/null | grep -oE '"id":"[0-9a-f]{64}"' | cut -d'"' -f4)
call $SEC1 "{\"method\":\"allowevent\",\"params\":[\"$APPROVED\"]}" >/dev/null
chk "allowevent admits that event past the allowlist" 1 \
  "$(timeout 10 noz event --sec "$SEC3" --ts $TS -c approved "$WS" 2>&1 | grep -c success)"

chk "supportedmethods lists the new methods" 1 \
  "$(has "$(call $SEC1 '{"method":"supportedmethods","params":[]}')" '"listdisallowedkinds"')"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
