#!/usr/bin/env bash
# Black-box tests for wisp features that require relay configuration:
# NIP-42 (AUTH), NIP-70 (protected events), NIP-13 (proof of work).
# The relay must already be running with the config matching <mode>:
#   auth      -> WISP_AUTH_REQUIRED=true, WISP_RELAY_URL set
#   protected -> WISP_RELAY_URL set (auth available, not required)
#   pow       -> WISP_MIN_POW_DIFFICULTY=8
#
# Usage: tests/integration_restrict.sh <relay-url> <auth|protected|pow>
# Requires: noz on PATH. Exits non-zero if any assertion fails.
set -u
R="${1:?relay url required}"
MODE="${2:?mode required (auth|protected|pow)}"
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

# publish and report ok|reject based on whether the relay accepted the event
pubres() { # noz-args...
  if timeout 10 noz event "$@" "$R" 2>&1 | grep -q 'success'; then echo ok; else echo reject; fi
}

case "$MODE" in
  auth)
    chk "NIP-42 publish without auth is rejected" reject "$(pubres --sec $SEC1 -c noauth)"
    chk "NIP-42 publish with auth is accepted" ok "$(pubres --sec $SEC1 --auth -c withauth)"
    ;;
  protected)
    chk "NIP-70 normal event without auth is accepted" ok "$(pubres --sec $SEC1 -c normal70)"
    chk "NIP-70 protected event without auth is rejected" reject "$(pubres --sec $SEC1 -t '-' -c prot70)"
    chk "NIP-70 protected event with auth is accepted" ok "$(pubres --sec $SEC1 --auth -t '-' -c prot70auth)"
    ;;
  pow)
    chk "NIP-13 event below difficulty is rejected" reject "$(pubres --sec $SEC1 -c lowpow)"
    chk "NIP-13 mined event is accepted" ok "$(pubres --sec $SEC1 --pow 8 -c minedpow)"
    ;;
  *)
    echo "unknown mode: $MODE" && exit 2
    ;;
esac

echo "-----"
echo "[$MODE] $pass passed, $fail failed"
[ "$fail" -eq 0 ]
