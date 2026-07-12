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

# publish and report ok|reject based on whether the relay accepted the event.
# Retries up to 4 times: a transient connect/read timeout under CI load (a fresh
# TCP connection per attempt) should not fail the suite, while a real rejection
# or a deterministic bug still reports reject after all attempts. The warmup gate
# below already establishes readiness, so this only absorbs the rarer mid-run blip.
pubres() { # noz-args...
  for attempt in 1 2 3 4; do
    if timeout 12 noz event "$@" "$R" 2>&1 | grep -q 'success'; then echo ok; return; fi
    [ -n "${NOZ_DEBUG_RETRIES:-}" ] && echo "pubres: attempt $attempt failed [noz event $*]" >&2
    [ "$attempt" -lt 4 ] && sleep 1
  done
  echo reject
}

# Block until the relay actually accepts an event of this mode's accepted class,
# not just until the TCP port is open. In CI the relay is started fresh per mode
# and `nc -z` only proves the listener is up, not that the event pipeline is
# ready; grading the first assertion against a still-warming relay is what made
# this suite flaky on main (a transient miss on an expected-accept assertion
# reports 'reject' and fails CI). Publishing an acceptable throwaway event until
# it succeeds converts "port open" into "pipeline ready", and is independent of
# noz's error-output format so it needs no reject-vs-timeout parsing.
warmup() {
  local args
  case "$MODE" in
    auth)      args=(--sec "$SEC1" --auth -c warmup) ;;
    protected) args=(--sec "$SEC1" -c warmup) ;;
    pow)       args=(--sec "$SEC1" --pow 8 -c warmup) ;;
    *)         return 0 ;; # unknown mode is reported by the assertion case below
  esac
  for i in $(seq 1 40); do
    timeout 12 noz event "${args[@]}" "$R" 2>&1 | grep -q 'success' && return 0
    sleep 0.5
  done
  echo "warmup: relay never accepted an event in '$MODE' mode after ~20s" >&2
  return 1
}

warmup || exit 1

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
