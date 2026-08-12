#!/usr/bin/env bash
# Black-box guard for the handover_list corruption fix: a WebSocket upgrade and a
# close-handover request landing in the same processSignal batch must not orphan
# connections.
#
# processSignal snapshots handover_list (takes head, clears inner) but leaves each
# node's next/prev intact. The .websocket branch is the only one that neither
# removes its node nor releases it, so a [websocket, close] chain used to have
# disown() call handover_list.remove() on a non-member, writing the live list's
# tail back to that stale node while head stayed null. Every handover inserted
# before the next drain was then unreachable: slot never released, fd never
# closed, and in no timeout list, so no sweep could ever reap it.
#
# The leak is invisible to unit tests and does not show up in
# wisp_connections_active (the orphans include plain HTTP conns), so this drives
# real connections and counts the relay's own socket fds afterwards. Measured on
# the unfixed build this reported 42 sockets still held; fixed, it reports ~1.
#
# The relay under test MUST be dedicated to this test and MUST be configured with
# a per-IP limit well above the concurrency below (e.g.
# WISP_MAX_CONNECTIONS_PER_IP=100000), otherwise connections are rejected by the
# limiter before they ever reach a handover and the test proves nothing. A single
# worker (WISP_WORKERS=1) concentrates every connection on one handover_list.
#
# Usage: tests/integration_handover_leak.sh [relay-url] [relay-pid]
# Requires: bash (uses /dev/tcp) and curl. Linux only (reads /proc/PID/fd).
#
# Exits non-zero if any assertion fails, so it can gate CI.
set -u
R="${1:-ws://127.0.0.1:7777}"
PID="${2:-}"
HOSTPORT="${R#ws://}"
HOSTPORT="${HOSTPORT%/}"
HOST="${HOSTPORT%%:*}"
PORT="${HOSTPORT##*:}"
ROUNDS="${ROUNDS:-40}"
PAIRS="${PAIRS:-12}"
# Must exceed the request + keepalive timeouts so every legitimate connection has
# been swept before we count what is left.
SETTLE="${SETTLE:-25}"
pass=0
fail=0

if [ -z "$PID" ]; then
  echo "FAIL - relay pid required as \$2 (needed to count the relay's own fds)"
  exit 1
fi
if [ ! -d "/proc/$PID/fd" ]; then
  echo "FAIL - /proc/$PID/fd not readable (Linux only, and pid must be the relay)"
  exit 1
fi

chk() { # desc expected actual
  if [ "$2" = "$3" ]; then
    echo "ok   - $1"
    pass=$((pass + 1))
  else
    echo "FAIL - $1 (expected '$2', got '$3')"
    fail=$((fail + 1))
  fi
}

sockets() { # count socket fds held by the relay
  local n=0 l
  for e in "/proc/$PID/fd"/*; do
    l="$(readlink "$e" 2>/dev/null)" || continue
    case "$l" in socket:*) n=$((n + 1)) ;; esac
  done
  printf '%s' "$n"
}

# A WebSocket upgrade that hands over as .websocket.
upgrade() {
  ( exec 3<>"/dev/tcp/$HOST/$PORT" || exit 0
    printf 'GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' "$HOSTPORT" >&3
    IFS= read -t 5 -r _ <&3 || true
    # Hold briefly so this connection's .websocket handover is still in the list
    # when a .close lands behind it. Closing immediately mostly misses the window.
    sleep 0.05
    exec 3>&- 3<&- ) 2>/dev/null &
}

# A plain HTTP request that hands over as .close.
closereq() {
  ( exec 3<>"/dev/tcp/$HOST/$PORT" || exit 0
    printf 'GET / HTTP/1.1\r\nHost: %s\r\nAccept: application/nostr+json\r\nConnection: close\r\n\r\n' "$HOSTPORT" >&3
    while IFS= read -t 5 -r _ <&3; do :; done || true
    exec 3>&- 3<&- ) 2>/dev/null &
}

# The relay must be serving before we trust any count.
srv="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$HOSTPORT/metrics" 2>/dev/null)"
chk "relay is serving before load" "200" "$srv"
[ "$fail" -eq 0 ] || { echo "-----"; echo "$pass passed, $fail failed"; exit 1; }

base="$(sockets)"
case "$base" in ''|*[!0-9]*) base=0 ;; esac
echo "info - baseline socket fds: $base"

for _ in $(seq 1 "$ROUNDS"); do
  for _ in $(seq 1 "$PAIRS"); do
    upgrade
    closereq
  done
  wait
done

sleep "$SETTLE"

# Measured first: a spinning relay pins a core at ~100% indefinitely, which is
# both the worst symptom and the fastest to detect. Unfixed, this burned 99.6%
# of a core continuously; fixed, the relay is idle here.
ticks() { # relay CPU ticks (utime + stime)
  local st
  st="$(cat "/proc/$PID/stat" 2>/dev/null)" || { printf '0'; return; }
  st="${st#*) }"
  awk -v x="$st" 'BEGIN{n=split(x,f," "); print f[12]+f[13]}'
}
hz="$(getconf CLK_TCK 2>/dev/null)"
case "$hz" in ''|*[!0-9]*) hz=100 ;; esac
t0="$(ticks)"
sleep 5
t1="$(ticks)"
burn=$((t1 - t0))
# 5 idle seconds should cost almost nothing. Fail past 30% of one core, far
# above idle noise and far below the ~100% a spin produces.
maxburn=$((hz * 5 * 30 / 100))
if [ "$burn" -le "$maxburn" ]; then
  echo "ok   - relay is not spinning while idle ($burn ticks over 5s, limit $maxburn)"
  pass=$((pass + 1))
else
  echo "FAIL - relay is spinning on orphaned connections ($burn ticks over 5s, limit $maxburn)"
  fail=$((fail + 1))
fi

after="$(sockets)"
case "$after" in ''|*[!0-9]*) after=999 ;; esac
echo "info - socket fds after load + ${SETTLE}s settle: $after"

# The fixed build sits flat at the baseline across runs; the slack is for the
# listener, the liveness probe's own connection and any in-flight teardown.
# Verified by mutation: reverting releaseHandover() back to disown() pushes this
# well past the threshold, while the fixed build stays at baseline.
limit=$((base + 5))
if [ "$after" -le "$limit" ]; then
  echo "ok   - no connections orphaned by interleaved handovers ($after <= $limit)"
  pass=$((pass + 1))
else
  echo "FAIL - connections orphaned by interleaved handovers ($after > $limit)"
  fail=$((fail + 1))
fi

# A leak that stalls the accept loop would show up here too.
srv="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$HOSTPORT/metrics" 2>/dev/null)"
chk "relay still serving after load" "200" "$srv"

echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
