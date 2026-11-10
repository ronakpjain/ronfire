#!/bin/sh
# Smoke test: boot the real binary on a Unix socket, curl it, shut it down.
# Usage: smoke.sh <path-to-ronfire-binary>
set -u

BIN="$1"
SOCK="/tmp/ronfire-smoke-$$.sock"
ROOT="$(mktemp -d /tmp/ronfire-smoke-root-XXXXXX)"
trap 'kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -f "$SOCK"; rm -rf "$ROOT"' EXIT

printf '<h1>Hello smoke</h1>' > "$ROOT/index.html"
printf '<h1>Page</h1>' > "$ROOT/page.html"

"$BIN" "$SOCK" --root "$ROOT" >/tmp/ronfire-smoke-out.log 2>&1 &
PID=$!

# Wait for the socket to appear.
for _ in $(seq 1 100); do
  [ -S "$SOCK" ] && break
  sleep 0.05
done
if [ ! -S "$SOCK" ]; then
  echo "socket never appeared" >&2
  cat /tmp/ronfire-smoke-out.log >&2
  exit 1
fi

fail() { echo "FAIL: $1" >&2; exit 1; }

BODY=$(curl -s --unix-socket "$SOCK" http://localhost/)
[ "$BODY" = '<h1>Hello smoke</h1>' ] || fail "index body: $BODY"

BODY=$(curl -s --unix-socket "$SOCK" http://localhost/page)
[ "$BODY" = '<h1>Page</h1>' ] || fail "friendly path body: $BODY"

CODE=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" http://localhost/missing)
[ "$CODE" = "404" ] || fail "missing code: $CODE"

# HEAD has headers but no body.
HEADERS=$(curl -sI --unix-socket "$SOCK" http://localhost/)
echo "$HEADERS" | grep -qi 'Connection: keep-alive' || fail "HEAD connection header: $HEADERS"
echo "$HEADERS" | grep -qi 'Accept-Ranges: bytes' || fail "HEAD accept-ranges: $HEADERS"

# Range request returns 206 with one byte.
CODE=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" -H 'Range: bytes=0-3' http://localhost/)
[ "$CODE" = "206" ] || fail "range code: $CODE"

# Write method is rejected.
CODE=$(curl -s -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" -X POST http://localhost/)
[ "$CODE" = "405" ] || fail "POST code: $CODE"

# Traversal is rejected.
CODE=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is --unix-socket "$SOCK" http://localhost/../etc/passwd)
[ "$CODE" = "400" ] || [ "$CODE" = "404" ] || fail "traversal code: $CODE"

echo "smoke: ok"
