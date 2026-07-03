#!/usr/bin/env bash
# Black-box guard for the WebSocket slot-leak fix (commit a521e10): a
# server-initiated idle close must run the epoll worker's cleanup path so the
# connection slot AND the per-IP connection-limiter bucket are reclaimed. A leak
# here is invisible to unit tests — it only manifests with a live epoll worker
# and the idle reaper — so this test drives real connections over the wire and
# reads the reclamation back from the /metrics gauge.
#
# The relay under test MUST be started with a short idle window and a per-IP
# limit of 2, e.g. WISP_IDLE_SECONDS=1 WISP_MAX_CONNECTIONS_PER_IP=2.
#
# Usage: tests/integration_ws_idle_reclaim.sh [relay-url]   (default ws://127.0.0.1:7777)
# Requires: bash (uses /dev/tcp) and curl on PATH. No noz needed — held-open idle
# connections are raw WebSocket handshakes so their idle timing is deterministic.
#
# Exits non-zero if any assertion fails, so it can gate CI.
set -u
R="${1:-ws://127.0.0.1:7777}"
LIMIT=2
HOSTPORT="${R#*://}"
HOSTPORT="${HOSTPORT%%/*}"
HOST="${HOSTPORT%%:*}"
PORT="${HOSTPORT##*:}"
METRICS="http://$HOSTPORT/metrics"
pass=0
fail=0
holders=()

chk() { # desc expected actual
  if [ "$2" = "$3" ]; then
    echo "ok   - $1"
    pass=$((pass + 1))
  else
    echo "FAIL - $1 (expected '$2', got '$3')"
    fail=$((fail + 1))
  fi
}

active() { # live connection count from the Prometheus gauge
  curl -s --max-time 5 "$METRICS" | awk '/^wisp_connections_active/{print $2}'
}

# Complete a WebSocket handshake and echo the HTTP status line. The RFC 6455
# example key is fine: wisp does not require it to be unique.
handshake() { # writes request on fd $1, reads the status line back
  printf 'GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' "$HOSTPORT" >&"$1"
}

# One-shot probe: open, handshake, return the status line, then close.
probe() {
  exec 3<>"/dev/tcp/$HOST/$PORT" || { echo "connect-failed"; return; }
  handshake 3
  local line
  IFS= read -r line <&3 || line="closed"
  exec 3>&- 3<&-
  line="${line%$'\r'}"
  # trim a trailing space left by an empty HTTP reason phrase (e.g. "429 ")
  printf '%s' "${line%"${line##*[![:space:]]}"}"
}

# Open an idle connection and hold it (backgrounded) until the server reaps it
# or we clean up. Records the handshake status line in $1.
hold() { # statusfile
  ( exec 3<>"/dev/tcp/$HOST/$PORT" || { echo "connect-failed" >"$1"; exit 1; }
    handshake 3
    IFS= read -r line <&3
    printf '%s' "${line%$'\r'}" >"$1"
    while :; do sleep 1; done ) &
  holders+=($!)
}

cleanup() { for p in "${holders[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT

base=$(active)
chk "metrics endpoint reports a numeric baseline" 1 "$([ -n "$base" ] && echo 1)"
base=${base:-0}

# Fill the per-IP bucket with LIMIT idle connections.
for i in $(seq 1 $LIMIT); do hold "/tmp/wsidle.$$.$i"; done
sleep 1
opened=0
for i in $(seq 1 $LIMIT); do
  s=$(cat "/tmp/wsidle.$$.$i" 2>/dev/null)
  [ "$s" = "HTTP/1.1 101 Switching Protocols" ] && opened=$((opened + 1))
done
chk "$LIMIT idle WebSocket connections upgraded" "$LIMIT" "$opened"
chk "active gauge rose by $LIMIT" "$((base + LIMIT))" "$(active)"

# Bucket is now full: a further connection from the same IP is refused.
chk "over-limit connection rejected (429)" "HTTP/1.1 429" "$(probe)"

# Wait for the server's idle reaper to close the held connections. The reaper
# ticks every 30s, so allow well past one tick.
reclaimed=""
for _ in $(seq 1 60); do
  [ "$(active)" = "$base" ] && { reclaimed=1; break; }
  sleep 1
done
# PRIMARY: the leaked-slot regression left this gauge stuck above baseline.
chk "connection slots reclaimed after idle close" "$base" "$(active)"

# SECONDARY: the same cleanup path frees the conn_limiter bucket, so LIMIT fresh
# connections must be accepted again. A leaked bucket would still return 429.
regained=0
for i in $(seq 1 $LIMIT); do hold "/tmp/wsidle2.$$.$i"; done
sleep 1
for i in $(seq 1 $LIMIT); do
  s=$(cat "/tmp/wsidle2.$$.$i" 2>/dev/null)
  [ "$s" = "HTTP/1.1 101 Switching Protocols" ] && regained=$((regained + 1))
done
chk "conn_limiter bucket reclaimed (reconnect up to limit)" "$LIMIT" "$regained"

rm -f "/tmp/wsidle.$$".* "/tmp/wsidle2.$$".* 2>/dev/null
echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
