#!/usr/bin/env bash
# NIP-86 relay management API test. The relay must be running with
# WISP_ADMIN_PUBKEYS set to SEC1's pubkey (below) and WISP_RELAY_URL set to the
# same <http-url> passed here (NIP-98 auth checks the URL).
#
# Usage: tests/integration_management.sh <http-url>   e.g. http://127.0.0.1:7781
# Requires: nak, curl, sha256sum on PATH. Exits non-zero if any assertion fails.
set -u
HTTP="${1:?http url required}"
WS="${HTTP/http:/ws:}"
SEC1=0000000000000000000000000000000000000000000000000000000000000001
SEC2=0000000000000000000000000000000000000000000000000000000000000002
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
has() { case "$1" in *"$2"*) echo 1 ;; *) echo 0 ;; esac; }
published() { nak event --sec "$1" -c "$2" "$WS" 2>&1 | grep -c success; }

# A NIP-86 call authorized with a NIP-98 (kind 27235) event signed by <sec>,
# including the required payload (sha256 of the body) tag.
call() { # sec body
  local sec=$1 body=$2 payload ev b64
  payload=$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)
  ev=$(nak event --sec "$sec" -k 27235 -t u="$HTTP" -t method=POST -t payload="$payload" -c "" 2>/dev/null)
  b64=$(printf '%s' "$ev" | base64 -w0)
  curl -s -X POST -H "Content-Type: application/nostr+json+rpc" \
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

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
