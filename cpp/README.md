# ronfire (C++)

C++ implementation of `ronfire`. No third-party deps in the server (C++20 + POSIX only).

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build
ctest --test-dir cpp/build
./cpp/build/ronfire /tmp/ronfire.sock --root ./static --config ./ronfire.conf
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
  blocks symlink escapes, `.`-paths/`app.log`/config file denied.
- Plugins: compiled-in only, strict `[plugin.NAME.INSTANCE]` INI. `proxy`
  (see below) is the only built-in.
- Runtime: single-threaded `poll()` loop + C++20 coroutines (`src/runtime/`).
  DNS and file reads are briefly synchronous; everything else is async.

## Proxy

Fixed-target `http` upstreams only: `route`, `url`, `content_type`,
`cache_seconds`, `timeout_seconds`, `max_bytes` (see `src/plugins/proxy.*`).
Timeouts → `504`, status/transport/oversize → `502`, fresh cache avoids
fetches, stale bodies serve when upstream fails.

`https://` URLs validate at startup but fail as `502` at fetch time: this
dependency-free build bundles no TLS. Add a TLS backend to `fetch()` in
`src/plugins/proxy.cpp` to support them.
