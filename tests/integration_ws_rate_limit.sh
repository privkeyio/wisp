#!/usr/bin/env bash
# Black-box coverage for wisp's per-IP per-minute EVENT and QUERY rate limits. The event limiter
# (src/handler.zig:271 -> ["OK",id,false,"rate-limited: too many events"], metrics.rateLimited) and
# the query limiter (src/handler.zig:456 -> ["CLOSED",sub,"rate-limited: too many queries"]) send
# their rejections over a live connection, so a unit test cannot observe them; this drives real
# traffic and reads the throttle back from the Prometheus counters that increment ONLY on the
# rate-limit path.
#
# The relay under test MUST be started dedicated, with tight limits matching LIMIT below, e.g.
#   WISP_EVENTS_PER_MINUTE=3 WISP_QUERIES_PER_MINUTE=3
# and no other client (the counter deltas expect this test's traffic only).
#
# Usage: tests/integration_ws_rate_limit.sh [relay-url]   (default ws://127.0.0.1:7787)
# Requires: noz + curl on PATH. Exits non-zero if any assertion fails, so it can gate CI.
set -u
R="${1:-ws://127.0.0.1:7787}"
LIMIT=3        # MUST match WISP_EVENTS_PER_MINUTE / WISP_QUERIES_PER_MINUTE the relay was started with
BURST=8        # > LIMIT so the excess is throttled
# The per-IP token bucket starts full (capacity = LIMIT) and refills at LIMIT/60 tokens/sec, i.e.
# ~0.05/sec here -- negligible over the ~1-2s burst. Allow one refill token of slack so a slow
# runner cannot flake: at least BURST-LIMIT-1 of the excess must be throttled.
MIN_THROTTLED=$((BURST - LIMIT - 1))
# A fixed test secret (same one the concurrency suite uses); events are valid + uniquely-tagged so a
# relay rejection can ONLY be the rate limit, never a bad signature / duplicate / disallowed kind.
SEC=0000000000000000000000000000000000000000000000000000000000000001

HOSTPORT="${R#*://}"
HOSTPORT="${HOSTPORT%%/*}"
PORT="${HOSTPORT##*:}"
case "$PORT" in
  '' | *[!0-9]*) echo "error: relay URL must include an explicit numeric port (got '$R')" >&2; exit 2 ;;
esac
METRICS="http://$HOSTPORT/metrics"
pass=0
fail=0

chk_ge() { # desc actual min
  if [ "${2:-0}" -ge "$3" ] 2>/dev/null; then
    echo "ok   - $1 (${2:-0} >= $3)"
    pass=$((pass + 1))
  else
    echo "FAIL - $1 (got '${2:-}', want >= $3)"
    fail=$((fail + 1))
  fi
}

metric() { # counter-name -> value (0 if absent)
  local v
  v=$(curl -s --max-time 5 "$METRICS" | awk -v k="$1" '$1 == k {print $2}')
  echo "${v:-0}"
}

# --- EVENTS: burst BURST valid, uniquely-tagged kind-1 events. The first LIMIT consume the bucket
# and are accepted (noz prints "success..."); the rest are throttled (noz prints "rejected..."). ---
base_ev=$(metric wisp_rate_limited_total)
acc=0
rej=0
for i in $(seq 1 "$BURST"); do
  out=$(timeout 8 noz event --sec "$SEC" -c "rl-ev-$i-$$" "$R" 2>&1 | tr -d '\n')
  case "$out" in
    success*) acc=$((acc + 1)) ;;
    rejected*) rej=$((rej + 1)) ;;
    *) echo "note - unexpected noz output for event $i: ${out:0:80}" ;;
  esac
done
now_ev=$(metric wisp_rate_limited_total)

chk_ge "some events accepted (throttle does not block everything)" "$acc" 1
chk_ge "excess events rejected by the relay" "$rej" "$MIN_THROTTLED"
chk_ge "wisp_rate_limited_total rose by the throttled events" "$((now_ev - base_ev))" "$MIN_THROTTLED"

# --- QUERIES: burst REQs from the same IP; the excess over the query limit is throttled with
# ["CLOSED",sub,"rate-limited: too many queries"], incrementing the query counter. ---
base_q=$(metric wisp_query_rate_limited_total)
for i in $(seq 1 "$BURST"); do
  timeout 6 noz req -k 1 -l 1 "$R" >/dev/null 2>&1
done
now_q=$(metric wisp_query_rate_limited_total)

chk_ge "wisp_query_rate_limited_total rose under a REQ burst" "$((now_q - base_q))" "$MIN_THROTTLED"

echo "== rate-limit: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
