//! Compiled plugin registry, configuration parsing, dispatch, and cache.
//!
//! Implementations are trusted Rust modules under `src/plugins`. This module
//! owns the object-safe [`PluginFactory`] and [`PluginHandler`] seam, builds a
//! fixed route table at startup, and performs exact path lookup. Configuration
//! selects only factories already registered in the binary; it cannot load
//! code or reload routes.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "proxy")]
use std::time::Duration;
#[cfg(feature = "proxy")]
use std::time::Instant;

#[cfg(feature = "proxy")]
use tokio::sync::Mutex;

use crate::http::{HttpRequest, HttpResponse, RequestRange, finalize_response};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Startup/configuration error with contextual section or line information.
pub struct ConfigError(String);

impl ConfigError {
    /// Creates a configuration error with a caller-provided explanation.
    ///
    /// Factories should use this additive API to report invalid instance names
    /// or fields; the registry adds section and line context while parsing.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    fn line(line: usize, message: impl fmt::Display) -> Self {
        Self::new(format!("line {line}: {message}"))
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}

/// Boxed future used to keep plugin dispatch object-safe.
pub type DispatchFuture = Pin<Box<dyn Future<Output = HttpResponse> + Send>>;

/// Request data passed across the plugin seam, retaining headers and range
/// semantics so plugins do not need to reparse the wire protocol.
#[derive(Clone, Debug)]
pub struct PluginRequest {
    /// The request method. The core server normally dispatches only `GET` and `HEAD`.
    pub method: String,
    /// The original origin-form target, including its query string.
    pub target: String,
    /// The query-free path used for exact route selection.
    pub path: String,
    /// Parsed request headers, retaining repeated names and their values.
    pub headers: Vec<(String, String)>,
    /// The parsed single-range state to be applied during finalization.
    pub range: RequestRange,
}

/// A compiled-in plugin owns request handling and any dependencies it needs.
/// The object-safe boxed future keeps core request parsing independent of
/// plugin implementations.
pub trait PluginHandler: Send + Sync {
    /// Returns the one absolute path owned by this configured instance.
    ///
    /// The registry rejects duplicate paths, and core dispatch compares this
    /// value exactly after removing only the request query from the path.
    fn route(&self) -> &str;
    /// Handles one already-parsed request and returns a buffered response.
    ///
    /// Implementations are trusted in-process code: the future must be
    /// `Send`, and the handler must be safe to share across connection tasks.
    /// [`dispatch_request`] applies range and `HEAD` finalization afterward.
    fn dispatch(
        &self,
        request: PluginRequest,
        cache: TtlCache,
    ) -> DispatchFuture;
}

/// Builds configured plugin instances from section fields.
pub trait PluginFactory: Send + Sync {
    /// Builds one configured handler from an instance name and its fields.
    ///
    /// Factories own validation, dependency setup, and the returned handler's
    /// state. Returning [`ConfigError`] aborts startup; configuration cannot
    /// load code or create a factory that was not registered at compile time.
    fn build(
        &self,
        instance: &str,
        fields: &BTreeMap<String, String>,
    ) -> Result<Arc<dyn PluginHandler>, ConfigError>;
}

/// Registry of compiled plugin factories keyed by configuration name.
#[derive(Clone, Default)]
pub struct PluginRegistry {
    factories: HashMap<String, Arc<dyn PluginFactory>>,
}

impl PluginRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one compiled factory under a strict plugin name.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        factory: Arc<dyn PluginFactory>,
    ) -> Result<(), ConfigError> {
        let name = name.into();
        if !valid_identifier(&name) {
            return Err(ConfigError::new(format!(
                "invalid plugin name {name:?}"
            )));
        }
        if self.factories.insert(name.clone(), factory).is_some() {
            return Err(ConfigError::new(format!(
                "duplicate plugin registration: {name}"
            )));
        }
        Ok(())
    }

    /// Registers the built-in plugins enabled by Cargo features.
    pub fn with_builtins() -> Result<Self, ConfigError> {
        #[allow(unused_mut)]
        let mut registry = Self::new();
        #[cfg(feature = "proxy")]
        registry.register("proxy", Arc::new(proxy::ProxyFactory::new()?))?;
        Ok(registry)
    }

    fn factory(&self, name: &str) -> Option<&Arc<dyn PluginFactory>> {
        self.factories.get(name)
    }
}

struct RawSection {
    plugin: String,
    instance: String,
    line: usize,
    fields: BTreeMap<String, String>,
}

/// Compiled route instances produced by the registry. Core dispatch only
/// performs exact route lookup and delegates to the owning plugin object.
/// Parsed and compiled plugin route instances.
///
/// A clone shares immutable handler ownership through `Arc`; it does not
/// reload the configuration. Route lookup is exact and performed in this
/// prebuilt vector, while each handler owns its plugin-specific behavior.
#[derive(Clone, Default)]
pub struct RouteConfig {
    routes: Vec<RegisteredRoute>,
}

#[derive(Clone)]
struct RegisteredRoute {
    path: String,
    handler: Arc<dyn PluginHandler>,
}

impl RouteConfig {
    /// Parses using the built-in compiled registry.
    pub fn parse(contents: &str) -> Result<Self, ConfigError> {
        let registry = PluginRegistry::with_builtins()?;
        Self::parse_with_registry(contents, &registry)
    }

    /// Parses sections and delegates each instance to its registered factory.
    pub fn parse_with_registry(
        contents: &str,
        registry: &PluginRegistry,
    ) -> Result<Self, ConfigError> {
        let mut sections = Vec::new();
        let mut current: Option<RawSection> = None;

        for (line_index, raw_line) in contents.lines().enumerate() {
            let line_number = line_index + 1;
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with(';')
            {
                continue;
            }

            if trimmed.starts_with('[') {
                if !trimmed.ends_with(']') {
                    return Err(ConfigError::line(
                        line_number,
                        "malformed section header",
                    ));
                }
                if let Some(section) = current.take() {
                    sections.push(section);
                }
                let section_name = &trimmed[1..trimmed.len() - 1];
                let Some(plugin_section) = section_name.strip_prefix("plugin.")
                else {
                    return Err(ConfigError::line(
                        line_number,
                        "section must use [plugin.NAME.INSTANCE]",
                    ));
                };
                let mut names = plugin_section.split('.');
                let Some(plugin) = names.next().filter(|name| !name.is_empty())
                else {
                    return Err(ConfigError::line(
                        line_number,
                        "missing plugin name",
                    ));
                };
                let Some(instance) =
                    names.next().filter(|name| !name.is_empty())
                else {
                    return Err(ConfigError::line(
                        line_number,
                        "missing plugin instance",
                    ));
                };
                if names.next().is_some()
                    || !valid_identifier(plugin)
                    || !valid_identifier(instance)
                {
                    return Err(ConfigError::line(
                        line_number,
                        "plugin and instance names must be simple identifiers",
                    ));
                }
                current = Some(RawSection {
                    plugin: plugin.to_string(),
                    instance: instance.to_string(),
                    line: line_number,
                    fields: BTreeMap::new(),
                });
                continue;
            }

            let Some(section) = current.as_mut() else {
                return Err(ConfigError::line(
                    line_number,
                    "key/value appears before a plugin section",
                ));
            };
            let Some((raw_key, raw_value)) = line.split_once('=') else {
                return Err(ConfigError::line(
                    line_number,
                    "expected key = value",
                ));
            };
            let key = raw_key.trim();
            let value = raw_value.trim();
            if !valid_identifier(key) {
                return Err(ConfigError::line(
                    line_number,
                    "malformed field name",
                ));
            }
            if section.fields.contains_key(key) {
                return Err(ConfigError::line(
                    line_number,
                    format!("duplicate field: {key}"),
                ));
            }
            section.fields.insert(key.to_string(), value.to_string());
        }
        if let Some(section) = current {
            sections.push(section);
        }

        let mut routes = Vec::with_capacity(sections.len());
        let mut instances = std::collections::HashSet::new();
        for section in sections {
            let instance_key =
                (section.plugin.clone(), section.instance.clone());
            if !instances.insert(instance_key) {
                return Err(ConfigError::line(
                    section.line,
                    "duplicate plugin instance",
                ));
            }
            let Some(factory) = registry.factory(&section.plugin) else {
                return Err(ConfigError::line(
                    section.line,
                    format!("unknown plugin: {}", section.plugin),
                ));
            };
            let handler = factory
                .build(&section.instance, &section.fields)
                .map_err(|error| ConfigError::line(section.line, error))?;
            let path = handler.route().to_string();
            if routes
                .iter()
                .any(|route: &RegisteredRoute| route.path == path)
            {
                return Err(ConfigError::line(
                    section.line,
                    format!("duplicate route: {path}"),
                ));
            }
            routes.push(RegisteredRoute { path, handler });
        }
        Ok(Self { routes })
    }

    /// Loads a configuration file; missing files are accepted only when
    /// `missing_allowed` is true.
    pub fn load(
        path: impl AsRef<Path>,
        registry: &PluginRegistry,
        missing_allowed: bool,
    ) -> Result<Self, ConfigError> {
        match fs::read_to_string(path.as_ref()) {
            Ok(contents) => Self::parse_with_registry(&contents, registry),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && missing_allowed =>
            {
                Ok(Self::default())
            }
            Err(error) => Err(ConfigError::new(format!(
                "cannot read config {}: {error}",
                path.as_ref().display()
            ))),
        }
    }

    fn route_for(&self, path: &str) -> Option<&RegisteredRoute> {
        self.routes.iter().find(|route| route.path == path)
    }

    #[cfg(test)]
    fn route_count(&self) -> usize {
        self.routes.len()
    }
}

/// Finds an exact route and delegates the parsed request to its plugin.
pub async fn dispatch_request(
    routes: &RouteConfig,
    request: &HttpRequest,
    cache: &TtlCache,
) -> Option<HttpResponse> {
    let route = routes.route_for(&request.path)?;
    let response = route
        .handler
        .dispatch(
            PluginRequest {
                method: request.method.clone(),
                target: request.target.clone(),
                path: request.path.clone(),
                headers: request.headers.clone(),
                range: request.range.clone(),
            },
            cache.clone(),
        )
        .await;
    Some(finalize_response(response, request))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
        })
}

#[cfg(feature = "proxy")]
pub(crate) fn validate_route_path(path: &str) -> Result<(), String> {
    if path.is_empty() || !path.starts_with('/') {
        return Err("route must start with /".to_string());
    }
    if path.contains(['?', '#', '\\', '\0'])
        || path.split('/').any(|part| part == "..")
        || path.chars().any(|character| {
            character.is_whitespace() || character.is_control()
        })
    {
        return Err(
            "route contains an invalid character or traversal component"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(feature = "proxy")]
pub(crate) fn validate_header_value(value: &str) -> Result<(), String> {
    if value.contains(['\r', '\n'])
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(
            "response header values must not contain control characters"
                .to_string(),
        );
    }
    Ok(())
}

/// Concurrency-safe in-memory cache storing successful plugin bodies and
/// retaining expired entries for stale-on-upstream-error responses.
///
/// The cache is shared by cloned server connection state. It is an optional
/// service passed to every plugin; handlers remain responsible for choosing
/// keys, TTLs, and whether stale data is safe to return.
#[derive(Clone, Default)]
pub struct TtlCache {
    #[cfg(feature = "proxy")]
    entries: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

#[cfg(feature = "proxy")]
#[derive(Clone)]
struct CacheEntry {
    body: Vec<u8>,
    expires_at: Instant,
}

impl TtlCache {
    /// Creates an empty cache shared by all connection tasks.
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "proxy")]
    pub(crate) async fn fresh(&self, key: &str) -> Option<Vec<u8>> {
        let entries = self.entries.lock().await;
        entries
            .get(key)
            .filter(|entry| Instant::now() < entry.expires_at)
            .map(|entry| entry.body.clone())
    }

    #[cfg(feature = "proxy")]
    pub(crate) async fn stale(&self, key: &str) -> Option<Vec<u8>> {
        let entries = self.entries.lock().await;
        entries.get(key).map(|entry| entry.body.clone())
    }

    #[cfg(feature = "proxy")]
    pub(crate) async fn put(&self, key: String, body: Vec<u8>, ttl: Duration) {
        let mut entries = self.entries.lock().await;
        entries.insert(
            key,
            CacheEntry {
                body,
                expires_at: Instant::now()
                    .checked_add(ttl)
                    .unwrap_or_else(Instant::now),
            },
        );
    }
}

#[cfg(feature = "proxy")]
pub mod proxy;

#[cfg(test)]
mod tests {

    use super::*;
    use crate::http::parse_http_request;

    struct TestFactory;
    struct TestHandler {
        route: String,
    }

    impl PluginFactory for TestFactory {
        fn build(
            &self,
            _instance: &str,
            fields: &BTreeMap<String, String>,
        ) -> Result<Arc<dyn PluginHandler>, ConfigError> {
            Ok(Arc::new(TestHandler {
                route: fields
                    .get("route")
                    .cloned()
                    .ok_or_else(|| ConfigError::new("missing route"))?,
            }))
        }
    }

    impl PluginHandler for TestHandler {
        fn route(&self) -> &str {
            &self.route
        }

        fn dispatch(
            &self,
            _request: PluginRequest,
            _cache: TtlCache,
        ) -> DispatchFuture {
            Box::pin(async {
                (
                    "HTTP/1.1 200 OK\r\n".to_string(),
                    "Content-Length: 2\r\n\r\n".to_string(),
                    b"ok".to_vec(),
                )
            })
        }
    }

    fn test_registry() -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        registry.register("test", Arc::new(TestFactory)).unwrap();
        registry
    }

    #[test]
    fn parses_ini_sections_and_registry_dispatch() {
        let registry = test_registry();
        let config = RouteConfig::parse_with_registry(
            "# comment\n\n[plugin.test.one]\nroute = /api/item\nvalue = fixed\n",
            &registry,
        )
        .unwrap();
        assert_eq!(config.route_count(), 1);
        assert!(config.route_for("/api/item").is_some());
    }

    #[test]
    fn rejects_unknown_plugins_duplicate_instances_routes_and_fields() {
        let registry = test_registry();
        assert!(
            RouteConfig::parse_with_registry(
                "[plugin.unknown.one]\nroute=/a",
                &registry
            )
            .is_err()
        );
        assert!(
            RouteConfig::parse_with_registry(
                "[plugin.test.one]\nroute=/a\n[plugin.test.one]\nroute=/b",
                &registry
            )
            .is_err()
        );
        assert!(
            RouteConfig::parse_with_registry(
                "[plugin.test.one]\nroute=/a\n[plugin.test.two]\nroute=/a",
                &registry
            )
            .is_err()
        );
        assert!(
            RouteConfig::parse_with_registry(
                "[plugin.test.one]\nroute",
                &registry
            )
            .is_err()
        );
        assert!(
            RouteConfig::parse_with_registry("route=/a", &registry).is_err()
        );
    }

    #[test]
    fn missing_config_is_only_allowed_when_requested() {
        let path = std::env::temp_dir().join(format!(
            "ronfire-missing-{}-{}.conf",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let _ = std::fs::remove_file(&path);
        let registry = test_registry();
        assert!(RouteConfig::load(&path, &registry, true).is_ok());
        assert!(RouteConfig::load(&path, &registry, false).is_err());
    }

    #[tokio::test]
    async fn generic_dispatch_matches_exact_routes_only() {
        let registry = test_registry();
        let config = RouteConfig::parse_with_registry(
            "[plugin.test.one]\nroute=/exact\n",
            &registry,
        )
        .unwrap();
        let query_request =
            parse_http_request(b"GET /exact?ignored=1 HTTP/1.1\r\n\r\n")
                .unwrap();
        assert!(
            dispatch_request(&config, &query_request, &TtlCache::new())
                .await
                .is_some()
        );
        let exact_request =
            parse_http_request(b"GET /exact HTTP/1.1\r\n\r\n").unwrap();
        assert!(
            dispatch_request(&config, &exact_request, &TtlCache::new())
                .await
                .is_some()
        );
    }
}
