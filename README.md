# ronfire

A fast Unix-socket HTTP server with static files and compiled-in plugins.
No third-party deps in the server beyond the system OpenSSL for proxy TLS
(C++20 + POSIX only).

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build
./build/ronfire /tmp/ronfire.sock --root ./static --config ./ronfire.conf
```

Layout: `src/main.cpp`, `src/runtime/` (coroutine event loop), `src/cli.*`,
`src/http.*`, `src/static_files.*`, `src/transport.*`, `src/server.*`,
`src/plugins.*`, `src/plugins/proxy.*`. Tests use system GoogleTest (test-only).

## Behavior

- Unix socket only (default `/tmp/ronfire.sock`); strict HTTP/1.0|1.1, 16 KiB
  headers, 30 s idle timeout, `Content-Length`/`Transfer-Encoding` rejected,
  single byte range (`206`/`416`), `HEAD` without body, keep-alive with
  `close` winning.
- Static files under `--root` (default `.`): `/` → `index.html`,
  extensionless → `name.html` or `name/index.html`, canonical containment
  blocks symlink escapes, `.`-paths/`app.log`/config file denied. Resolved
  paths and file responses are cached (invalidated by mtime+size).
- Plugins: compiled-in only, strict `[plugin.NAME.INSTANCE]` INI. `proxy`
  (see below) is the only built-in.
- Runtime: single-threaded `poll()` loop + coroutines (`src/runtime/`).
  DNS and file reads are briefly synchronous; everything else is async.

## Proxy

Fixed-target `http` upstreams only: `route`, `url`, `content_type`,
`cache_seconds`, `timeout_seconds`, `max_bytes` (see `src/plugins/proxy.*`).
Timeouts → `504`, status/transport/oversize → `502`, fresh cache avoids
fetches, stale bodies serve when upstream fails.

`https://` upstreams work via a system OpenSSL TLS client (see
`src/plugins/proxy.cpp`).

## Docker

```bash
docker build -t ronfire .
docker run -v ./static:/app:ro -v ./ronfire.conf:/etc/ronfire.conf:ro \
  ronfire /run/ronfire/ronfire.sock --root /app --config /etc/ronfire.conf
```
