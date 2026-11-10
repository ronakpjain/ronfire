#!/bin/sh
# Benchmarks the server over a Unix socket (3 runs, median).
set -u

ROOT="./static"
CONNS=32
PROCS=4
SECS=6
RUNS=3

sock=/tmp/bench.sock
rm -f "$sock"
./build/ronfire "$sock" --root "$ROOT" >/tmp/bench.log 2>&1 &
pid=$!
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.05; done
[ -S "$sock" ] || { echo "no socket"; exit 1; }

for path in "/" "/Resume.pdf"; do
  echo "== $path =="
  for i in $(seq 1 $RUNS); do
    python3 ./tests/bench.py "$sock" "$path" "$CONNS" "$SECS" "$PROCS" | python3 -c "
import sys, json
vals = [json.loads(l)['rps'] for l in sys.stdin if l.strip()]
vals.sort()
print(round(vals[len(vals)//2]))"
  done | python3 -c "
import sys
vals = sorted(int(l.strip()) for l in sys.stdin if l.strip())
print('median rps:', vals[len(vals)//2])"
done

kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
