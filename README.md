# ronfire

`ronfire` is a small Tokio HTTP server over a Unix domain socket. Static and
friendly routes remain local, while optional compiled-in plugins can own
additional route behavior.

## Architecture and source layout

Requests are strictly parsed and framed in `src/http.rs`, dispatched by exact
path through the compiled registry in `src/plugins`, then resolved beneath the
secure document root in `src/static_files.rs` when no plugin owns the route.
Responses are finalized for ranges/HEAD and written by `src/transport.rs`; the
runtime composition and configuration startup live in `src/server.rs`, with
CLI parsing in `src/cli.rs`.

```text
src/lib.rs                 crate docs and compatibility re-exports
src/http.rs                HTTP parsing, framing, ranges, finalization
src/server.rs              startup and connection-task composition
src/static_files.rs        document-root containment and static responses
src/transport.rs           Unix socket writes and logging
src/plugins/mod.rs         registry, config parser, dispatch, cache
src/plugins/proxy.rs       feature-gated fixed-target proxy
```

Plugin implementations live separately under `src/plugins`. Configuration only
enables already-compiled and registered plugins; it cannot dynamically load
code or reload configuration. Plugins are trusted, unsandboxed in-process Rust
code and their responses are buffered. To implement one, **fork ronfire** and
register your fork's implementation. See the concise overview below and the
[compiled plugin guide](docs/plugins.md) for the complete walkthrough.

## Run

```bash
cargo run -- /tmp/ronfire.sock
cargo run -- /tmp/ronfire.sock --config ./ronfire.conf
```

The positional socket argument remains compatible and defaults to
`/tmp/ronfire.sock`. The default configuration is `ronfire.conf`; its absence
is allowed. A path supplied explicitly with `--config` must exist and be
readable. `--config PATH` and `--config=PATH` are accepted.

### Docker Compose

The image intentionally contains the ronfire binary only. Mount website
content read-only as the document root, keep the private configuration outside
that root, and share the Unix socket with the edge proxy:

```yaml
services:
  ronfire:
    image: ironic06/ronfire:0.3.0
    command:
      - /run/ronfire/ronfire.sock
      - --root
      - /app
      - --config
      - /etc/ronfire/ronfire.conf
    volumes:
      - ./website:/app:ro
      - ./ronfire.conf:/etc/ronfire/ronfire.conf:ro
      - ronfire-socket:/run/ronfire

  edge:
    image: caddy:alpine
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ronfire-socket:/run/ronfire

volumes:
  ronfire-socket:
```

The mounted `Caddyfile` uses the same socket path inside the shared volume:

```caddyfile
localhost {
    reverse_proxy unix//run/ronfire/ronfire.sock
    tls internal
}
```

## Compiled plugins and configuration

Plugins are compiled into the binary and registered by name. Core request
parsing and static serving only perform exact route lookup, then delegate to an
object-safe plugin handler, so adding a plugin does not require changing those
parts of the server. The default build includes the `proxy` plugin. Users who
need another plugin must **fork ronfire** to add its implementation under
`src/plugins`, feature gate it, and register its factory; a config section alone
cannot add executable behavior. See [docs/plugins.md](docs/plugins.md) for
lifecycle, security boundaries, and a practical fork walkthrough.

`ronfire.conf` uses strict INI-like sections. Each section is
`[plugin.NAME.INSTANCE]`, followed by `key = value` fields. Blank lines and
whole-line `#` or `;` comments are allowed. The built-in proxy fields are
`route`, `url`, `content_type`, optional `content_disposition`, optional
`redirect_hosts`, `cache_seconds`, `timeout_seconds`, and `max_bytes`:

```ini
# Generic fixed-target endpoint; this is not application-specific.
[plugin.proxy.report]
route = /api/report
url = https://api.example.test/report
content_type = application/json
content_disposition =
redirect_hosts = api.example.test
cache_seconds = 30
timeout_seconds = 10
max_bytes = 1048576
```

Unknown plugins or fields, malformed sections/values, duplicate plugin
instances, and duplicate routes fail startup with line-numbered errors. Proxy
routes match the configured path exactly (the request query is not part of the
match), and the upstream URL is always the configured fixed URL. A request can
never supply or override a destination URL. Route paths must be safe absolute
URL paths; targets must be valid `http` or `https` URLs without userinfo;
integer limits are validated; and response header values reject control
characters including CR/LF.

The proxy uses native Rust reqwest with rustls, follows redirects through a
finite policy restricted to the original host by default (use
`redirect_hosts = github.com, release-assets.githubusercontent.com` when
needed), requires a successful upstream status, applies a timeout, and
reads `Response::chunk` incrementally so `max_bytes` is enforced without an
unbounded body read. Timeout failures produce 504; failed status, transport,
and oversized responses produce 502. Successful bodies use the configured
Content-Type and optional Content-Disposition with an exact Content-Length.
An in-memory concurrency-safe TTL cache is keyed by route. Expired entries are
retained and served when a subsequent upstream request fails.

## Features, TLS, and container runtime

Cargo's default features include `proxy`. To build the static/core server
without the proxy dependency, use `cargo build --no-default-features`; proxy
configuration will then be rejected as an unknown plugin. The `proxy` feature
owns the optional reqwest dependency, with default reqwest features disabled
and only rustls TLS plus its bundled `webpki-roots` enabled. Consequently the
Alpine image needs no external fetch utility or system CA package for the
bundled roots. Deployments that intentionally switch to native certificate
roots should add `ca-certificates` to the runtime image.

## Static files and security

`--root PATH` selects one explicit document root and defaults to `.` for
backward compatibility. Friendly paths resolve only inside that root:
`/` maps to `index.html`, and extensionless paths use `name.html` or
`name/index.html`. A dedicated root such as `--root ./static` is recommended
for deployments. Canonicalization prevents symlink escapes, the active config
file and `app.log` are denied, and dot/VCS metadata paths are rejected. Only
GET and HEAD on HTTP/1.0 or HTTP/1.1 are accepted, traversal components are
rejected, and the server listens on a Unix socket; Caddy or another local
reverse proxy can provide edge TLS.

Static and proxy success responses advertise `Accept-Ranges: bytes` and
support one byte range. Valid ranges return 206; malformed or unsatisfiable
ranges return 416 with `Content-Range: bytes */LENGTH`. HEAD returns the same
headers as GET without a body. PDFs are served as `application/pdf`.

HTTP headers are buffered per connection up to 16 KiB, with a finite idle read
timeout. Extra bytes are retained for pipelined requests. GET and HEAD bodies
and transfer encoding are rejected; malformed, timed-out, and oversized
headers produce 400, 408, and 431 responses respectively. Request logging goes
to stderr for container logging and does not create a public log file.
