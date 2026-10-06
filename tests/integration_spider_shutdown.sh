#!/usr/bin/env bash
# Spider shutdown guard: a relay whose spider is still bootstrapping the admin's
# contact list from a slow upstream must keep serving, and must exit promptly on
# SIGTERM instead of waiting out the bootstrap read window.
#
# The upstream is a stand-in relay that completes the WebSocket handshake, takes
# the bootstrap REQ, and never answers it. The bootstrap loop gives such a relay
# 10s; it has to notice the shutdown flag between its 1s reads rather than run
# that window to the end. The test also requires the relay to be listening while
# the bootstrap is in flight, which fails if the bootstrap moves back onto the
# startup path ahead of the listener.
#
# Self-contained: it starts both the stand-in upstream and the spider relay, so
# it takes the wisp binary rather than a URL. Ports and the exit bound can be
# overridden with SPIDER_PORT, UPSTREAM_PORT and EXIT_BOUND_S.
#
# Usage: tests/integration_spider_shutdown.sh <path-to-wisp>
# Requires: python3 and nc on PATH. Exits non-zero if any assertion fails.
set -u
WISP="${1:?path to the wisp binary required}"
SPIDER_PORT="${SPIDER_PORT:-7790}"
UPSTREAM_PORT="${UPSTREAM_PORT:-7791}"
# The bootstrap read window is 10s, so a loop that ignores shutdown cannot exit
# inside this bound; a shutdown-aware one needs about 2s (1s read + 1s tick).
EXIT_BOUND_S="${EXIT_BOUND_S:-6}"
ADMIN=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
pass=0
fail=0
upstream_pid=
relay_pid=
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/spidershutdown.XXXXXX")"

cleanup() {
  for p in $relay_pid $upstream_pid; do kill -9 "$p" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$tmpdir"
}
trap cleanup EXIT

chk() { # desc expected actual
  if [ "$2" = "$3" ]; then
    echo "ok   - $1"
    pass=$((pass + 1))
  else
    echo "FAIL - $1 (expected '$2', got '$3')"
    fail=$((fail + 1))
  fi
}

# Stand-in upstream: answers the handshake, logs each frame it receives, and
# never replies to any of them.
python3 -I -u - "$UPSTREAM_PORT" >"$tmpdir/upstream.log" 2>&1 <<'PY' &
import base64, hashlib, socket, sys, threading

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def serve(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return
        data += chunk
    key = b""
    for line in data.split(b"\r\n"):
        if line.lower().startswith(b"sec-websocket-key:"):
            key = line.split(b":", 1)[1].strip()
    accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
    conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    print("handshake", flush=True)
    buf = data.split(b"\r\n\r\n", 1)[1]
    while True:
        # client frames are always masked: 2 header bytes, extended length, 4-byte mask
        while len(buf) >= 2:
            n, hdr = buf[1] & 0x7F, 2
            if n == 126:
                n, hdr = int.from_bytes(buf[2:4], "big"), 4
            elif n == 127:
                n, hdr = int.from_bytes(buf[2:10], "big"), 10
            if len(buf) < hdr + 4 + n:
                break
            mask = buf[hdr:hdr + 4]
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(buf[hdr + 4:hdr + 4 + n]))
            buf = buf[hdr + 4 + n:]
            print("frame", payload[:40].decode("utf-8", "replace"), flush=True)
        chunk = conn.recv(65536)
        if not chunk:
            return
        buf += chunk

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1])))
srv.listen()
print("listening", flush=True)
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
PY
upstream_pid=$!
for _ in $(seq 1 40); do grep -q listening "$tmpdir/upstream.log" 2>/dev/null && break; sleep 0.25; done
chk "stand-in upstream listening" 1 "$(grep -c listening "$tmpdir/upstream.log" 2>/dev/null)"

env WISP_HOST=127.0.0.1 WISP_PORT="$SPIDER_PORT" WISP_STORAGE_PATH="$tmpdir/db" \
  WISP_SPIDER_ENABLED=true WISP_SPIDER_ADMIN="$ADMIN" \
  WISP_SPIDER_RELAYS="ws://127.0.0.1:$UPSTREAM_PORT" \
  "$WISP" relay >"$tmpdir/relay.log" 2>&1 &
relay_pid=$!

# The bootstrap is in flight once the upstream has its REQ frame.
in_flight=0
for _ in $(seq 1 80); do grep -q '^frame \["REQ","bootstrap"' "$tmpdir/upstream.log" && { in_flight=1; break; }; sleep 0.1; done
chk "bootstrap REQ reached the slow upstream" 1 "$in_flight"

# The spider starts before the listener binds (and before the signal handler is
# installed), so allow a moment for both rather than probing once.
listening=0
for _ in $(seq 1 30); do nc -z 127.0.0.1 "$SPIDER_PORT" 2>/dev/null && { listening=1; break; }; sleep 0.1; done
chk "relay listens while the bootstrap is in flight" 1 "$listening"

start=$(date +%s%N)
kill -TERM "$relay_pid" 2>/dev/null
exited=0
for _ in $(seq 1 $((EXIT_BOUND_S * 10))); do
  kill -0 "$relay_pid" 2>/dev/null || { exited=1; break; }
  sleep 0.1
done
elapsed_ms=$((($(date +%s%N) - start) / 1000000))
echo "     SIGTERM to exit: ${elapsed_ms}ms (bound ${EXIT_BOUND_S}s)"
chk "relay exits within ${EXIT_BOUND_S}s of SIGTERM during bootstrap" 1 "$exited"
if [ "$exited" = 1 ]; then
  wait "$relay_pid" 2>/dev/null
  chk "relay shut down cleanly" 0 "$?"
  relay_pid=
fi

if [ "$fail" -ne 0 ]; then
  echo "--- relay log"; cat "$tmpdir/relay.log"
  echo "--- upstream log"; cat "$tmpdir/upstream.log"
fi
echo "-----"
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
