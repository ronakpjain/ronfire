#!/usr/bin/env python3
"""Benchmark ronfire variants over a Unix socket (stdlib only, asyncio).

Usage: bench.py <socket> <path> <conns> <seconds> <procs>
Prints one JSON line per process: {"rps": ..., "p50_ms": ..., "p95_ms": ...}
"""
import asyncio
import json
import sys
import multiprocessing as mp

SOCKET, PATH, CONNS, SECONDS, PROCS = (
    sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5]))

REQ = ("GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
       % PATH).encode()

async def worker():
    latencies = []
    count = 0
    reader, writer = await asyncio.open_unix_connection(SOCKET)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SECONDS
    pending = bytearray()
    while True:
        t0 = loop.time()
        if t0 >= deadline:
            break
        writer.write(REQ)
        await writer.drain()
        head_end = pending.find(b"\r\n\r\n")
        while head_end < 0:
            chunk = await reader.read(65536)
            if not chunk:
                break
            pending += chunk
            head_end = pending.find(b"\r\n\r\n")
        if head_end < 0:
            break
        head = bytes(pending[:head_end]).decode("latin1")
        clen = 0
        for line in head.split("\r\n")[1:]:
            if line.lower().startswith("content-length:"):
                clen = int(line.split(":", 1)[1].strip())
        rest = pending[head_end + 4:]
        while len(rest) < clen:
            chunk = await reader.read(65536)
            if not chunk:
                break
            rest += chunk
        pending = bytearray(rest[clen:])
        latencies.append(loop.time() - t0)
        count += 1
    try:
        writer.close()
    except Exception:
        pass
    return count, latencies

async def main():
    results = await asyncio.gather(*[worker() for _ in range(CONNS)])
    total = sum(c for c, _ in results)
    all_lat = sorted(l for _, lats in results for l in lats)
    if not all_lat:
        return json.dumps({"rps": 0.0, "p50_ms": 0.0, "p95_ms": 0.0})
    p = lambda q: all_lat[min(len(all_lat) - 1, int(q * len(all_lat)))] * 1000.0
    return json.dumps({"rps": round(total / SECONDS * PROCS, 1),
                       "p50_ms": round(p(0.50), 3),
                       "p95_ms": round(p(0.95), 3)})

def run(_):
    print(asyncio.run(main()), flush=True)

if __name__ == "__main__":
    with mp.Pool(PROCS) as pool:
        pool.map(run, range(PROCS))
