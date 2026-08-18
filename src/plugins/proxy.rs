//! Feature-gated fixed-target HTTP proxy plugin.
//!
//! Each configured instance owns a validated upstream URL and a redirect
//! allowlist. Native reqwest/rustls fetches successful bodies incrementally
//! under timeout and size limits; the plugin never accepts a destination URL
//! from a request. Core response finalization supplies range and `HEAD`
//! behavior after the proxy returns its buffered body.

use super::{
    ConfigError, DispatchFuture, HttpResponse, PluginFactory, PluginHandler,
    PluginRequest, TtlCache, validate_header_value, validate_route_path,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::redirect::Policy;

#[derive(Debug, Clone, PartialEq, Eq)]
/// Fixed-target proxy configuration compiled from one plugin section.
pub struct ProxyConfig {
    /// Exact local route path.
    pub route: String,
    /// Fixed HTTP(S) upstream URL.
    pub url: String,
    /// Safe response Content-Type value.
    pub content_type: String,
    /// Optional safe Content-Disposition value.
    pub content_disposition: Option<String>,
    /// Case-insensitive host allowlist for redirects.
    pub redirect_hosts: Vec<String>,
    /// Successful-body cache lifetime; zero disables caching.
    pub cache_seconds: u64,
    /// Maximum complete upstream operation duration.
    pub timeout_seconds: u64,
    /// Incremental response body limit.
    pub max_bytes: usize,
}

/// Upstream timeout, size, status, or transport failures.
#[derive(Debug)]
pub enum ProxyError {
    /// The complete upstream operation exceeded its configured timeout.
    Timeout,
    /// Incremental body reading crossed the configured byte limit.
    Oversize,
    /// Reqwest could not send the request or read its response.
    Request(reqwest::Error),
    /// The upstream completed with a non-success HTTP status.
    Status(StatusCode),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("upstream request timed out"),
            Self::Oversize => {
                formatter.write_str("upstream response exceeded max_bytes")
            }
            Self::Request(error) => {
                write!(formatter, "upstream request failed: {error}")
            }
            Self::Status(status) => {
                write!(formatter, "upstream returned HTTP {status}")
            }
        }
    }
}
impl std::error::Error for ProxyError {}

/// Boxed fetch future used by the native reqwest implementation and tests.
pub type FetchFuture =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, ProxyError>> + Send>>;

/// Abstracts upstream fetching so proxy boundaries can be tested without
/// public network access.
pub trait ProxyFetcher: Send + Sync {
    /// Fetches one fixed URL with a body limit and operation timeout.
    ///
    /// Implementations must enforce `max_bytes` while consuming the response,
    /// rather than reading an unbounded body first. This seam is public so
    /// tests and specialized in-process fetchers can avoid a real network.
    fn fetch(
        &self,
        url: &str,
        max_bytes: usize,
        timeout: Duration,
    ) -> FetchFuture;
}

#[derive(Clone)]
struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ProxyFetcher for ReqwestFetcher {
    fn fetch(
        &self,
        url: &str,
        max_bytes: usize,
        timeout: Duration,
    ) -> FetchFuture {
        let client = self.client.clone();
        let url = url.to_string();
        Box::pin(async move {
            let request = async move {
                let mut response = client
                    .get(url)
                    .send()
                    .await
                    .map_err(ProxyError::Request)?;
                if !response.status().is_success() {
                    return Err(ProxyError::Status(response.status()));
                }
                let mut body = Vec::new();
                while let Some(chunk) =
                    response.chunk().await.map_err(ProxyError::Request)?
                {
                    if body.len().saturating_add(chunk.len()) > max_bytes {
                        return Err(ProxyError::Oversize);
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(body)
            };
            match tokio::time::timeout(timeout, request).await {
                Ok(result) => result,
                Err(_) => Err(ProxyError::Timeout),
            }
        })
    }
}

/// Compiled factory that creates one reqwest client per proxy instance.
pub struct ProxyFactory;

impl ProxyFactory {
    /// Creates a proxy factory; client construction is deferred per instance.
    pub fn new() -> Result<Self, ConfigError> {
        Ok(Self)
    }
}

impl PluginFactory for ProxyFactory {
    fn build(
        &self,
        _instance: &str,
        fields: &BTreeMap<String, String>,
    ) -> Result<Arc<dyn PluginHandler>, ConfigError> {
        let allowed = BTreeSet::from([
            "route",
            "url",
            "content_type",
            "content_disposition",
            "redirect_hosts",
            "cache_seconds",
            "timeout_seconds",
            "max_bytes",
        ]);
        if let Some(field) = fields
            .keys()
            .find(|field| !allowed.contains(field.as_str()))
        {
            return Err(ConfigError::new(format!(
                "unknown proxy field: {field}"
            )));
        }
        let required = |name: &str| {
            fields
                .get(name)
                .filter(|value| !value.is_empty())
                .cloned()
                .ok_or_else(|| {
                    ConfigError::new(format!("missing proxy field: {name}"))
                })
        };
        let route = required("route")?;
        validate_route_path(&route).map_err(ConfigError::new)?;
        let url = required("url")?;
        let parsed_url = validate_url(&url)?;
        let redirect_hosts = parse_redirect_hosts(
            fields.get("redirect_hosts").map(String::as_str),
            parsed_url.host_str().ok_or_else(|| {
                ConfigError::new("proxy url must contain a host")
            })?,
        )?;
        let content_type = required("content_type")?;
        validate_header_value(&content_type).map_err(ConfigError::new)?;
        let content_disposition = fields
            .get("content_disposition")
            .filter(|value| !value.is_empty())
            .cloned();
        if let Some(value) = &content_disposition {
            validate_header_value(value).map_err(ConfigError::new)?;
        }
        let cache_seconds = parse_integer(fields, "cache_seconds", true)?;
        let timeout_seconds = parse_integer(fields, "timeout_seconds", false)?;
        let max_bytes_u64 = parse_integer(fields, "max_bytes", false)?;
        let max_bytes = usize::try_from(max_bytes_u64)
            .map_err(|_| ConfigError::new("max_bytes is too large"))?;
        let client = build_client(&redirect_hosts)?;
        Ok(Arc::new(ProxyPlugin {
            config: Arc::new(ProxyConfig {
                route,
                url,
                content_type,
                content_disposition,
                redirect_hosts,
                cache_seconds,
                timeout_seconds,
                max_bytes,
            }),
            fetcher: Arc::new(ReqwestFetcher { client }),
        }))
    }
}

/// A configured proxy plugin handler with its own redirect policy.
///
/// The handler retains its fixed upstream URL and never uses request data as a
/// destination. It is constructed by [`ProxyFactory`] and shared across tasks.
pub struct ProxyPlugin {
    config: Arc<ProxyConfig>,
    fetcher: Arc<dyn ProxyFetcher>,
}

impl ProxyPlugin {
    #[cfg(test)]
    fn with_fetcher(
        config: ProxyConfig,
        fetcher: Arc<dyn ProxyFetcher>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            fetcher,
        }
    }
}

impl PluginHandler for ProxyPlugin {
    fn route(&self) -> &str {
        &self.config.route
    }

    fn dispatch(
        &self,
        _request: PluginRequest,
        cache: TtlCache,
    ) -> DispatchFuture {
        let config = self.config.clone();
        let fetcher = self.fetcher.clone();
        Box::pin(async move { dispatch_proxy(&config, fetcher, cache).await })
    }
}

async fn dispatch_proxy(
    config: &ProxyConfig,
    fetcher: Arc<dyn ProxyFetcher>,
    cache: TtlCache,
) -> HttpResponse {
    if config.cache_seconds > 0
        && let Some(body) = cache.fresh(&config.route).await
    {
        return proxy_response(config, body);
    }

    match fetcher
        .fetch(
            &config.url,
            config.max_bytes,
            Duration::from_secs(config.timeout_seconds),
        )
        .await
    {
        Ok(body) => {
            if config.cache_seconds > 0 {
                cache
                    .put(
                        config.route.clone(),
                        body.clone(),
                        Duration::from_secs(config.cache_seconds),
                    )
                    .await;
            }
            proxy_response(config, body)
        }
        Err(error) => {
            if let Some(body) = cache.stale(&config.route).await {
                return proxy_response(config, body);
            }
            if matches!(error, ProxyError::Timeout) {
                error_response(
                    "HTTP/1.1 504 Gateway Timeout\r\n",
                    &error.to_string(),
                )
            } else {
                error_response(
                    "HTTP/1.1 502 Bad Gateway\r\n",
                    &error.to_string(),
                )
            }
        }
    }
}

fn proxy_response(config: &ProxyConfig, body: Vec<u8>) -> HttpResponse {
    let disposition = config
        .content_disposition
        .as_ref()
        .map_or(String::new(), |value| {
            format!("Content-Disposition: {value}\r\n")
        });
    (
        "HTTP/1.1 200 OK\r\n".to_string(),
        format!(
            "Content-Length: {}\r\nContent-Type: {}\r\n{disposition}\r\n",
            body.len(),
            config.content_type
        ),
        body,
    )
}

fn error_response(status: &str, message: &str) -> HttpResponse {
    let body = format!("<h1>{message}</h1>").into_bytes();
    (
        status.to_string(),
        format!(
            "Content-Length: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
            body.len()
        ),
        body,
    )
}

fn parse_integer(
    fields: &BTreeMap<String, String>,
    name: &str,
    allow_zero: bool,
) -> Result<u64, ConfigError> {
    let value = fields.get(name).ok_or_else(|| {
        ConfigError::new(format!("missing proxy field: {name}"))
    })?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError::new(format!(
            "proxy field {name} must be a non-negative integer"
        )));
    }
    let parsed = value.parse::<u64>().map_err(|_| {
        ConfigError::new(format!("proxy field {name} is too large"))
    })?;
    if !allow_zero && parsed == 0 {
        return Err(ConfigError::new(format!(
            "proxy field {name} must be greater than zero"
        )));
    }
    Ok(parsed)
}

fn validate_url(value: &str) -> Result<reqwest::Url, ConfigError> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| ConfigError::new("proxy url must be a valid URL"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(ConfigError::new("proxy url must use http or https"));
    }
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(ConfigError::new(
            "proxy url must contain a host and no userinfo",
        ));
    }
    Ok(url)
}

fn parse_redirect_hosts(
    value: Option<&str>,
    original_host: &str,
) -> Result<Vec<String>, ConfigError> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return Ok(vec![original_host.to_ascii_lowercase()]);
    };
    let hosts = value
        .split(',')
        .map(str::trim)
        .map(validate_host)
        .collect::<Result<Vec<_>, _>>()?;
    if hosts.is_empty() {
        return Err(ConfigError::new("redirect_hosts must not be empty"));
    }
    Ok(hosts)
}

fn validate_host(host: &str) -> Result<String, ConfigError> {
    if host.is_empty()
        || host.len() > 253
        || host.bytes().any(|byte| {
            !byte.is_ascii_alphanumeric() && byte != b'.' && byte != b'-'
        })
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
    {
        return Err(ConfigError::new(format!(
            "invalid redirect host: {host:?}"
        )));
    }
    Ok(host.to_ascii_lowercase())
}

fn redirect_allowed(
    url: &reqwest::Url,
    allowed_hosts: &[String],
    previous_count: usize,
) -> bool {
    previous_count < 10
        && url.host_str().is_some_and(|host| {
            allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        })
}

fn build_client(
    allowed_hosts: &[String],
) -> Result<reqwest::Client, ConfigError> {
    let allowed_hosts = allowed_hosts.to_vec();
    let policy = Policy::custom(move |attempt| {
        if redirect_allowed(
            attempt.url(),
            &allowed_hosts,
            attempt.previous().len(),
        ) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    reqwest::Client::builder()
        .redirect(policy)
        .build()
        .map_err(|error| {
            ConfigError::new(format!("proxy client setup failed: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RequestRange;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockFetcher {
        calls: AtomicUsize,
        result: Result<Vec<u8>, &'static str>,
    }

    impl ProxyFetcher for MockFetcher {
        fn fetch(
            &self,
            _url: &str,
            _max_bytes: usize,
            _timeout: Duration,
        ) -> FetchFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.result.clone();
            Box::pin(async move {
                match result {
                    Ok(body) => Ok(body),
                    Err("timeout") => Err(ProxyError::Timeout),
                    Err("oversize") => Err(ProxyError::Oversize),
                    Err(_) => Err(ProxyError::Status(StatusCode::BAD_GATEWAY)),
                }
            })
        }
    }

    fn request() -> PluginRequest {
        PluginRequest {
            method: "GET".to_string(),
            target: "/api/item".to_string(),
            path: "/api/item".to_string(),
            headers: Vec::new(),
            range: RequestRange::None,
        }
    }

    fn config(cache_seconds: u64) -> ProxyConfig {
        ProxyConfig {
            route: "/api/item".to_string(),
            url: "https://example.test/item".to_string(),
            content_type: "application/json".to_string(),
            content_disposition: None,
            redirect_hosts: vec!["example.test".to_string()],
            cache_seconds,
            timeout_seconds: 1,
            max_bytes: 100,
        }
    }

    #[test]
    fn proxy_factory_rejects_unknown_and_bad_fields() {
        let factory = ProxyFactory::new().unwrap();
        let mut fields = BTreeMap::from([
            ("route".to_string(), "/api/item".to_string()),
            ("url".to_string(), "https://example.test/item".to_string()),
            ("content_type".to_string(), "text/plain".to_string()),
            ("cache_seconds".to_string(), "0".to_string()),
            ("timeout_seconds".to_string(), "1".to_string()),
            ("max_bytes".to_string(), "10".to_string()),
            ("redirect_hosts".to_string(), "example.test".to_string()),
        ]);
        assert!(factory.build("one", &fields).is_ok());
        fields.insert("unknown".to_string(), "x".to_string());
        assert!(factory.build("one", &fields).is_err());
    }

    #[test]
    fn redirect_hosts_default_and_reject_unsafe_hosts() {
        assert_eq!(
            parse_redirect_hosts(None, "Example.TEST").unwrap(),
            vec!["example.test"]
        );
        assert_eq!(
            parse_redirect_hosts(
                Some("github.com, release-assets.githubusercontent.com"),
                "example.test"
            )
            .unwrap(),
            vec!["github.com", "release-assets.githubusercontent.com"]
        );
        assert!(
            parse_redirect_hosts(Some("example.test:443"), "example.test")
                .is_err()
        );
        let allowed = vec!["example.test".to_string()];
        assert!(redirect_allowed(
            &reqwest::Url::parse("https://example.test/next").unwrap(),
            &allowed,
            0
        ));
        assert!(!redirect_allowed(
            &reqwest::Url::parse("https://evil.test/next").unwrap(),
            &allowed,
            0
        ));
        assert!(!redirect_allowed(
            &reqwest::Url::parse("https://example.test/next").unwrap(),
            &allowed,
            10
        ));
    }

    #[tokio::test]
    async fn proxy_cache_and_stale_error_behavior() {
        let fetcher = Arc::new(MockFetcher {
            calls: AtomicUsize::new(0),
            result: Ok(br#"{"ok":true}"#.to_vec()),
        });
        let plugin = ProxyPlugin::with_fetcher(config(60), fetcher.clone());
        let cache = TtlCache::new();
        let first = plugin.dispatch(request(), cache.clone()).await;
        let second = plugin.dispatch(request(), cache.clone()).await;
        assert_eq!(first.2, second.2);
        assert_eq!(fetcher.calls.load(Ordering::SeqCst), 1);

        let failed = Arc::new(MockFetcher {
            calls: AtomicUsize::new(0),
            result: Err("failed"),
        });
        let stale = ProxyPlugin::with_fetcher(config(60), failed)
            .dispatch(request(), cache)
            .await;
        assert_eq!(stale.2, first.2);
    }

    #[tokio::test]
    async fn proxy_timeout_and_oversize_are_gateway_errors() {
        for error in ["timeout", "oversize"] {
            let plugin = ProxyPlugin::with_fetcher(
                config(0),
                Arc::new(MockFetcher {
                    calls: AtomicUsize::new(0),
                    result: Err(error),
                }),
            );
            let response = plugin.dispatch(request(), TtlCache::new()).await;
            assert!(response.0.starts_with("HTTP/1.1 5"));
            assert!(response.1.contains("Content-Length:"));
        }
    }
}
