# Compiled-in plugins

ronfire's plugin system is a compile-time extension point, not a runtime module
loader. Implementations live separately under `src/plugins`; a configuration
file can only enable an implementation that was already compiled into the
binary and registered in `PluginRegistry::with_builtins`. Configuration never
loads Rust, a shared library, or a script.

## Lifecycle and request flow

At startup, `server::run` performs this sequence:

1. `PluginRegistry::with_builtins` constructs the registry. Each Cargo feature
   owns the optional dependency for its plugin and registers that plugin's
   `PluginFactory` here.
2. `RouteConfig::load` reads the selected configuration file (or accepts the
   absent default file), parses `[plugin.NAME.INSTANCE]` sections, and looks up
   `NAME` in the registry.
3. The factory validates the fields and constructs one `PluginHandler` for the
   instance. Invalid fields, unknown plugins, duplicate instances, and
   duplicate routes stop startup with a `ConfigError`.
4. The resulting immutable route table and shared `TtlCache` are cloned into
   connection tasks. There is no configuration reload: changing a file has no
   effect until the process is restarted.
5. `http::read_http_request` strictly frames and parses a request. The core
   server rejects unsupported methods before dispatch.
6. `plugins::dispatch_request` removes no additional routing information: it
   looks up the parsed query-free `request.path` by exact equality, creates a
   `PluginRequest` containing the original target, headers, and range state,
   and awaits the selected handler. `/reports` does not match `/reports/today`.
7. The handler returns a buffered `HttpResponse` (`status`, `headers`, body
   bytes). Core finalization applies one byte range and `HEAD` semantics, then
   transport writes the complete response to the Unix socket.

A plugin is trusted, unsandboxed Rust code in the server process. It can use
CPU, memory, filesystem, network, and any dependencies enabled by its Cargo
feature, and a panic or blocking operation can affect the server. Validate
configuration at factory construction, bound network/body work, avoid blocking
async tasks, and treat untrusted plugin code as equivalent to modifying the
server itself. ronfire intentionally provides no process sandbox.

Responses are buffered as `Vec<u8>` before sending; the `PluginHandler` API has
no streaming response type. This makes finalization and exact
`Content-Length` straightforward, but a plugin must impose sensible body
limits. There is no dynamic loading and no config reload.

## Configuration format

The parser accepts blank lines and whole-line `#` or `;` comments. A section
has exactly one simple plugin name and instance name:

```ini
[plugin.NAME.INSTANCE]
key = value
another_key = value
```

Keys and names are simple identifiers containing ASCII letters, digits, `_`,
or `-`. A field belongs to the current section; fields before a section,
duplicate fields, malformed headers, and unknown fields are errors. Factories
receive fields as a `BTreeMap<String, String>` and should reject anything they
do not understand. A factory can create a useful error for callers with the
public additive API `ConfigError::new("explanation")`; the registry adds the
configuration line to that error.

For the default `proxy` feature, a complete instance looks like this:

```ini
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

`route`, `url`, and `content_type` are required. `content_disposition` and
`redirect_hosts` may be empty. The proxy validates an absolute safe route, a
fixed `http` or `https` URL without userinfo, safe response header values, and
positive timeout/size limits. Redirects are finite and restricted to the
original host unless `redirect_hosts` explicitly lists additional hosts.

## Cache, ranges, and finalization

The built-in proxy optionally caches successful bodies by configured route.
`cache_seconds = 0` disables caching. A fresh entry avoids an upstream request;
expired entries remain available as stale data when a later upstream request
fails. Successful fetches replace the entry. Timeout failures without stale
data return 504; status, transport, and size failures return 502.

The cache is an in-memory service shared across connections and is not durable.
A custom plugin receives a clone of `TtlCache` and may use it, but it owns the
meaning and safety of its cache key and values. Do not cache private responses
without implementing the required policy yourself.

After a handler returns, core finalization—not the plugin—applies the parsed
single byte range and `HEAD` behavior. Successful responses advertise
`Accept-Ranges: bytes`; valid ranges become 206 with `Content-Range`, while
malformed or unsatisfiable ranges become 416. `HEAD` retains the GET headers
and `Content-Length` but sends no body. A plugin should return a normal 200
response with the full buffered body and let core perform these transformations.

## Implementing a plugin: fork ronfire

Users should **FORK ronfire** to implement plugins. Do not expect a plugin
crate or configuration alone to add executable behavior: the implementation
must be reviewed, compiled, and registered into your fork. Keep the fork's
plugin source separate under `src/plugins`.

The following is a practical outline for a plugin named `your_plugin`. It uses
only the public API and can be adapted directly (the example body is fixed so
the handler is independently testable):

### 1. Add the implementation

Create `src/plugins/your_plugin.rs`:

```rust
use super::{
    ConfigError, DispatchFuture, PluginFactory, PluginHandler, PluginRequest,
    TtlCache,
};
use std::collections::BTreeMap;
use std::sync::Arc;

pub struct YourPluginFactory;

impl YourPluginFactory {
    pub fn new() -> Self {
        Self
    }
}

impl PluginFactory for YourPluginFactory {
    fn build(
        &self,
        _instance: &str,
        fields: &BTreeMap<String, String>,
    ) -> Result<Arc<dyn PluginHandler>, ConfigError> {
        let route = fields
            .get("route")
            .filter(|value| value.starts_with('/'))
            .cloned()
            .ok_or_else(|| ConfigError::new("your_plugin requires route"))?;
        Ok(Arc::new(YourPlugin { route }))
    }
}

struct YourPlugin {
    route: String,
}

impl PluginHandler for YourPlugin {
    fn route(&self) -> &str {
        &self.route
    }

    fn dispatch(
        &self,
        _request: PluginRequest,
        _cache: TtlCache,
    ) -> DispatchFuture {
        Box::pin(async {
            let body = b"hello from your plugin".to_vec();
            (
                "HTTP/1.1 200 OK\r\n".to_string(),
                format!(
                    "Content-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                ),
                body,
            )
        })
    }
}
```

Real implementations should validate every field, bound all work, and keep
secrets out of error strings. For an async implementation, clone the owned
configuration into the future and use a non-blocking client. The handler is
unsandboxed and receives the original request metadata, so apply any
plugin-specific authorization and input validation yourself.

### 2. Make dependencies feature-owned (if needed)

In your fork's `Cargo.toml`, add an optional dependency and a feature that
owns it:

```toml
[features]
default = ["proxy"]
your_plugin = ["dep:your-client"]

[dependencies]
your-client = { version = "1", optional = true }
```

Do not make a plugin dependency unconditional. A build with
`--no-default-features` should omit both the plugin and its dependencies.

### 3. Declare and register it

In `src/plugins/mod.rs`, declare the module behind the same feature and add
its factory to `with_builtins`:

```rust
#[cfg(feature = "your_plugin")]
pub mod your_plugin;

// inside PluginRegistry::with_builtins, beside the proxy registration:
#[cfg(feature = "your_plugin")]
registry.register(
    "your_plugin",
    Arc::new(your_plugin::YourPluginFactory::new()),
)?;
```

The registration name is the `NAME` used in configuration. This explicit step
is what keeps implementations compiled in and makes the configuration surface
auditable.

### 4. Add a config instance

```ini
[plugin.your_plugin.status]
route = /api/status
```

The factory receives `status` as `instance` and `route` in `fields`. The route
must be unique among all plugin instances and is matched exactly. A query such
as `/api/status?verbose=1` still dispatches to `/api/status`; the plugin can
inspect `PluginRequest::target` if it needs the query, but it must validate it.

### 5. Test and build the fork

Add unit tests for field validation, route ownership, response bounds, and
failure behavior. Test dispatch with a `PluginRequest` and `TtlCache::new()`;
use a mock dependency rather than making network calls in unit tests. Then run:

```bash
cargo fmt --check
cargo test --all-targets --all-features
cargo test --no-default-features
cargo check --no-default-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Only after the fork's implementation, feature gate, registry entry, config,
and tests agree should the feature be enabled in deployment.
