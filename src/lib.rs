//! Core request framing, secure static serving, caching, and compiled-plugin
//! dispatch for ronfire. The public APIs deliberately keep request parsing and
//! document-root security in the core while allowing feature-gated plugins to
//! own their dependencies and upstream behavior.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "proxy")]
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

/// A small serialized stderr logger suitable for concurrent connection tasks.
/// It retains the historical async API without creating a file inside the
/// document root.
#[derive(Clone)]
pub struct AsyncLogger {
    file_mutex: Arc<Mutex<()>>,
}

impl Default for AsyncLogger {
    fn default() -> Self {
        Self {
            file_mutex: Arc::new(Mutex::new(())),
        }
    }
}

impl AsyncLogger {
    /// Creates a logger that writes timestamped messages to stderr.
    pub fn new() -> Self {
        Self::default()
    }

    /// Writes one message while preserving line ordering between tasks.
    pub async fn log(&self, message: &str) {
        let _lock = self.file_mutex.lock().await;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        eprintln!("[{timestamp}] {message}");
    }
}

/// Creates a Unix domain socket, replacing an existing socket at the path.
pub fn create_socket(socket_path: String) -> std::io::Result<UnixListener> {
    if Path::new(&socket_path).exists() {
        let _ = fs::remove_file(&socket_path);
    }
    UnixListener::bind(socket_path)
}

/// A parsed request line and header block.
///
/// `path` is the query-free request path used for exact routing. GET and HEAD
/// requests intentionally reject all Content-Length and Transfer-Encoding
/// framing, so no body can be confused with a pipelined request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    /// The HTTP method as received.
    pub method: String,
    /// The original origin-form request target, including any query string.
    pub target: String,
    /// The normalized path used by static and plugin routing.
    pub path: String,
    /// The accepted HTTP protocol version.
    pub version: String,
    /// Header names and trimmed values, preserving repeated headers.
    pub headers: Vec<(String, String)>,
    /// The parsed single-range request, if one was supplied.
    pub range: RequestRange,
}

impl HttpRequest {
    /// Returns the first header with a case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Computes persistence from every Connection header; `close` always wins.
    pub fn keep_alive(&self) -> bool {
        let connection_values = self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
            .map(|(_, value)| value.as_str());
        let mut has_close = false;
        let mut has_keep_alive = false;
        for value in connection_values {
            for token in value.split(',').map(str::trim) {
                has_close |= token.eq_ignore_ascii_case("close");
                has_keep_alive |= token.eq_ignore_ascii_case("keep-alive");
            }
        }
        if has_close {
            return false;
        }
        has_keep_alive || self.version == "HTTP/1.1"
    }

    /// Reports whether the response must have HEAD semantics.
    pub fn is_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("HEAD")
    }
}

/// Parsed range state. Invalid and unsatisfiable ranges are distinguished
/// from no Range header so callers can return HTTP 416 correctly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestRange {
    None,
    Single(ByteRangeSpec),
    Invalid,
}

/// One RFC-style byte range before it is resolved against a body length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteRangeSpec {
    /// Inclusive start, or `None` for a suffix range.
    pub start: Option<u64>,
    /// Inclusive end, or `None` for an open-ended range.
    pub end: Option<u64>,
}

/// Errors produced while reading or parsing a bounded request header block.
#[derive(Debug)]
pub enum RequestReadError {
    Io(std::io::Error),
    HeaderTooLarge,
    Malformed(String),
}

impl fmt::Display for RequestReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => {
                write!(formatter, "request read failed: {error}")
            }
            Self::HeaderTooLarge => {
                formatter.write_str("request headers exceed limit")
            }
            Self::Malformed(message) => formatter.write_str(message),
        }
    }
}
impl std::error::Error for RequestReadError {}

/// Maximum bytes consumed for one request's headers, including delimiters.
pub const MAX_REQUEST_HEADER_BYTES: usize = 16 * 1024;
/// Maximum time allowed to receive one complete request header block.
pub const REQUEST_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Reads exactly one CRLFCRLF-terminated request while retaining any later
/// bytes in the supplied buffered reader for pipelined requests.
pub async fn read_http_request<R>(
    reader: &mut R,
) -> Result<Option<HttpRequest>, RequestReadError>
where
    R: AsyncBufRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let byte = match reader.read_u8().await {
            Ok(byte) => byte,
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                if bytes.is_empty() {
                    return Ok(None);
                }
                return Err(RequestReadError::Malformed(
                    "connection closed before request headers completed"
                        .to_string(),
                ));
            }
            Err(error) => return Err(RequestReadError::Io(error)),
        };
        bytes.push(byte);
        if bytes.len() >= 4 && bytes[bytes.len() - 4..] == *b"\r\n\r\n" {
            return parse_http_request(&bytes).map(Some);
        }
        if bytes.len() >= MAX_REQUEST_HEADER_BYTES {
            return Err(RequestReadError::HeaderTooLarge);
        }
    }
}

/// Parses one complete CRLF-terminated HTTP request header block.
///
/// The parser is intentionally strict about framing: any Content-Length or
/// Transfer-Encoding on GET/HEAD is rejected before dispatch.
pub fn parse_http_request(
    bytes: &[u8],
) -> Result<HttpRequest, RequestReadError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        RequestReadError::Malformed("request is not UTF-8 headers".to_string())
    })?;
    let Some(header_block) = text.strip_suffix("\r\n\r\n") else {
        return Err(RequestReadError::Malformed(
            "request headers must end with CRLFCRLF".to_string(),
        ));
    };
    let mut lines = header_block.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        RequestReadError::Malformed("missing request line".to_string())
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty()
        || target.is_empty()
        || version.is_empty()
        || parts.next().is_some()
    {
        return Err(RequestReadError::Malformed(
            "malformed request line".to_string(),
        ));
    }
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(RequestReadError::Malformed(
            "unsupported HTTP version".to_string(),
        ));
    }
    if !target.starts_with('/') || target.contains(['#', '\\', '\0']) {
        return Err(RequestReadError::Malformed(
            "invalid request target".to_string(),
        ));
    }
    let path = target.split('?').next().unwrap_or(target);
    if path.is_empty() || path.split('/').any(|part| part == "..") {
        return Err(RequestReadError::Malformed(
            "invalid or traversing path".to_string(),
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(RequestReadError::Malformed(
                "malformed header".to_string(),
            ));
        };
        let name = name.trim();
        let value = value.trim();
        if !is_header_token(name)
            || value.bytes().any(|byte| byte < 0x20 && byte != b'\t')
        {
            return Err(RequestReadError::Malformed(
                "invalid header".to_string(),
            ));
        }
        headers.push((name.to_string(), value.to_string()));
    }
    let request = HttpRequest {
        method: method.to_string(),
        target: target.to_string(),
        path: path.to_string(),
        version: version.to_string(),
        range: match headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("range"))
            .collect::<Vec<_>>()
            .as_slice()
        {
            [] => RequestRange::None,
            [(_, value)] => match parse_range_header(value) {
                Ok(range) => RequestRange::Single(range),
                Err(_) => RequestRange::Invalid,
            },
            _ => RequestRange::Invalid,
        },
        headers,
    };
    if request.header("transfer-encoding").is_some() {
        return Err(RequestReadError::Malformed(
            "transfer-encoding is not supported".to_string(),
        ));
    }
    if request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
    {
        return Err(RequestReadError::Malformed(
            "GET and HEAD bodies or content-length framing are not supported"
                .to_string(),
        ));
    }
    Ok(request)
}

fn is_header_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Indicates that a Range header is not a single valid byte range.
pub struct RangeParseError;

/// Parses a single `bytes=start-end`, `bytes=start-`, or suffix range.
/// Multiple ranges are rejected because responses support one range only.
pub fn parse_range_header(
    value: &str,
) -> Result<ByteRangeSpec, RangeParseError> {
    let value = value.strip_prefix("bytes=").ok_or(RangeParseError)?;
    if value.is_empty()
        || value.contains(',')
        || value.contains(char::is_whitespace)
    {
        return Err(RangeParseError);
    }
    let (start, end) = value.split_once('-').ok_or(RangeParseError)?;
    if start.is_empty() && end.is_empty() {
        return Err(RangeParseError);
    }
    if start.is_empty() {
        let suffix = end.parse::<u64>().map_err(|_| RangeParseError)?;
        if suffix == 0 {
            return Err(RangeParseError);
        }
        return Ok(ByteRangeSpec {
            start: None,
            end: Some(suffix),
        });
    }
    let start = start.parse::<u64>().map_err(|_| RangeParseError)?;
    let end = if end.is_empty() {
        None
    } else {
        Some(end.parse::<u64>().map_err(|_| RangeParseError)?)
    };
    if end.is_some_and(|end| end < start) {
        return Err(RangeParseError);
    }
    Ok(ByteRangeSpec {
        start: Some(start),
        end,
    })
}

fn resolved_range(
    spec: &ByteRangeSpec,
    length: usize,
) -> Option<(usize, usize)> {
    if length == 0 {
        return None;
    }
    let length = length as u64;
    let (start, end) = match (spec.start, spec.end) {
        (Some(start), Some(end)) => (start, end.min(length - 1)),
        (Some(start), None) => (start, length - 1),
        (None, Some(suffix)) => (length.saturating_sub(suffix), length - 1),
        (None, None) => return None,
    };
    if start >= length || start > end {
        None
    } else {
        Some((start as usize, end as usize))
    }
}

/// Applies range and HEAD semantics to a complete response.
///
/// Successful full responses advertise byte range support; HEAD retains GET
/// headers but drops the body. Invalid or unsatisfiable ranges become 416 with
/// a `Content-Range: bytes */length` header.
pub fn finalize_response(
    mut response: HttpResponse,
    request: &HttpRequest,
) -> HttpResponse {
    let original_length = response.2.len();
    let successful = response.0.starts_with("HTTP/1.1 200 ");
    if successful {
        response.1 = set_header(&response.1, "Accept-Ranges", "bytes");
    }
    if successful {
        match &request.range {
            RequestRange::Invalid => {
                response.0 =
                    "HTTP/1.1 416 Range Not Satisfiable\r\n".to_string();
                response.1 = set_header(
                    &response.1,
                    "Content-Range",
                    &format!("bytes */{original_length}"),
                );
                response.2 = b"<h1>416 Range Not Satisfiable</h1>".to_vec();
                response.1 = set_header(
                    &response.1,
                    "Content-Length",
                    &response.2.len().to_string(),
                );
            }
            RequestRange::Single(spec) => {
                let Some((start, end)) = resolved_range(spec, original_length)
                else {
                    response.0 =
                        "HTTP/1.1 416 Range Not Satisfiable\r\n".to_string();
                    response.1 = set_header(
                        &response.1,
                        "Content-Range",
                        &format!("bytes */{original_length}"),
                    );
                    response.2 = b"<h1>416 Range Not Satisfiable</h1>".to_vec();
                    response.1 = set_header(
                        &response.1,
                        "Content-Length",
                        &response.2.len().to_string(),
                    );
                    if request.is_head() {
                        response.2.clear();
                    }
                    return response;
                };
                response.0 = "HTTP/1.1 206 Partial Content\r\n".to_string();
                response.1 = set_header(
                    &response.1,
                    "Content-Range",
                    &format!("bytes {start}-{end}/{original_length}"),
                );
                response.2 = response.2[start..=end].to_vec();
                response.1 = set_header(
                    &response.1,
                    "Content-Length",
                    &response.2.len().to_string(),
                );
            }
            RequestRange::None => {
                response.1 = set_header(
                    &response.1,
                    "Content-Length",
                    &original_length.to_string(),
                );
            }
        }
    }
    if request.is_head() {
        response.2.clear();
    }
    response
}

fn set_header(headers: &str, name: &str, value: &str) -> String {
    let mut result = headers
        .split("\r\n")
        .filter(|line| {
            !line.is_empty()
                && !line
                    .split_once(':')
                    .is_some_and(|(key, _)| key.eq_ignore_ascii_case(name))
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    result.push(format!("{name}: {value}"));
    format!("{}\r\n\r\n", result.join("\r\n"))
}

/// Backwards-compatible request parser returning a resolved static file under
/// the current directory.
/// Parses a legacy request string and returns its query-free GET/HEAD path.
pub async fn parse_request_path(
    request: &str,
    logger: Option<&AsyncLogger>,
) -> Option<String> {
    let parsed = parse_http_request(request.as_bytes()).ok()?;
    if parsed.method != "GET" && parsed.method != "HEAD" {
        log_message(
            logger,
            format!("Unsupported HTTP Method: {}", parsed.method),
        )
        .await;
        return None;
    }
    Some(parsed.path)
}

/// Resolves a legacy request using the current directory as its document root.
pub async fn parse_request(
    request: &str,
    logger: Option<&AsyncLogger>,
) -> Option<String> {
    let path = parse_request_path(request, logger).await?;
    DocumentRoot::new(".", None)
        .ok()?
        .resolve(&path)
        .map(|path| path.to_string_lossy().to_string())
}

/// A canonical document root enforcing containment and denied-file policy.
#[derive(Clone, Debug)]
pub struct DocumentRoot {
    canonical_root: PathBuf,
    denied: Vec<PathBuf>,
}

impl DocumentRoot {
    /// Canonicalizes a directory and optionally denies one canonical file.
    pub fn new(
        root: impl AsRef<Path>,
        denied: Option<&Path>,
    ) -> std::io::Result<Self> {
        let canonical_root = fs::canonicalize(root)?;
        if !canonical_root.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "document root is not a directory",
            ));
        }
        let denied = denied
            .map(fs::canonicalize)
            .transpose()?
            .into_iter()
            .collect();
        Ok(Self {
            canonical_root,
            denied,
        })
    }

    /// Resolves a path with friendly index/extension fallbacks, rejecting
    /// symlink escapes, dot metadata, denied files, and application logs.
    pub fn resolve(&self, path: &str) -> Option<PathBuf> {
        let relative = path.trim_start_matches('/');
        if !relative.is_empty()
            && (relative.contains("//")
                || relative.split('/').any(|part| part.starts_with('.')))
        {
            return None;
        }
        let candidates = if relative.is_empty() {
            vec![self.canonical_root.join("index.html")]
        } else if relative.ends_with('/') {
            vec![self.canonical_root.join(relative).join("index.html")]
        } else if Path::new(relative).extension().is_none() {
            vec![
                self.canonical_root.join(format!("{relative}.html")),
                self.canonical_root.join(relative).join("index.html"),
            ]
        } else {
            vec![self.canonical_root.join(relative)]
        };
        candidates.into_iter().find_map(|candidate| {
            let canonical = candidate.canonicalize().ok()?;
            if !canonical.starts_with(&self.canonical_root)
                || self.denied.contains(&canonical)
                || canonical.file_name().is_some_and(|name| name == "app.log")
                || !canonical.is_file()
            {
                None
            } else {
                Some(canonical)
            }
        })
    }
}

pub fn generate_response(full_path: &str) -> HttpResponse {
    match fs::read(full_path) {
        Ok(contents) => {
            let headers = format!(
                "Content-Length: {}\r\nContent-Type: {}\r\nAccept-Ranges: bytes\r\n\r\n",
                contents.len(),
                guess_mime_type(full_path)
            );
            ("HTTP/1.1 200 OK\r\n".to_string(), headers, contents)
        }
        Err(_) => {
            let body = b"<h1>404 Not Found</h1>".to_vec();
            let headers = format!(
                "Content-Length: {}\r\nContent-Type: text/html\r\n\r\n",
                body.len()
            );
            ("HTTP/1.1 404 Not Found\r\n".to_string(), headers, body)
        }
    }
}

fn guess_mime_type(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|s| s.to_str()) {
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain",
        Some("wasm") => "application/wasm",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("ogg") => "audio/ogg",
        Some("mp3") => "audio/mpeg",
        _ => "application/octet-stream",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Startup/configuration error with contextual section or line information.
pub struct ConfigError(String);

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
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

/// Complete HTTP response parts: status line, headers, and body.
pub type HttpResponse = (String, String, Vec<u8>);
/// Boxed future used to keep plugin dispatch object-safe.
pub type DispatchFuture = Pin<Box<dyn Future<Output = HttpResponse> + Send>>;

/// Request data passed across the plugin seam, retaining headers and range
/// semantics so plugins do not need to reparse the wire protocol.
#[derive(Clone, Debug)]
pub struct PluginRequest {
    pub method: String,
    pub target: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub range: RequestRange,
}

/// A compiled-in plugin owns request handling and any dependencies it needs.
/// The object-safe boxed future keeps core request parsing independent of
/// plugin implementations.
pub trait PluginHandler: Send + Sync {
    fn route(&self) -> &str;
    fn dispatch(
        &self,
        request: PluginRequest,
        cache: TtlCache,
    ) -> DispatchFuture;
}

/// Builds configured plugin instances from section fields.
pub trait PluginFactory: Send + Sync {
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
pub mod proxy {
    use super::{
        ConfigError, DispatchFuture, HttpResponse, PluginFactory,
        PluginHandler, PluginRequest, TtlCache, validate_header_value,
        validate_route_path,
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
        Timeout,
        Oversize,
        Request(reqwest::Error),
        Status(StatusCode),
    }

    impl fmt::Display for ProxyError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Timeout => {
                    formatter.write_str("upstream request timed out")
                }
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
            let timeout_seconds =
                parse_integer(fields, "timeout_seconds", false)?;
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
    /// A configured proxy plugin handler with its own redirect policy.
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
            Box::pin(
                async move { dispatch_proxy(&config, fetcher, cache).await },
            )
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
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
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
                        Err(_) => {
                            Err(ProxyError::Status(StatusCode::BAD_GATEWAY))
                        }
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
                let response =
                    plugin.dispatch(request(), TtlCache::new()).await;
                assert!(response.0.starts_with("HTTP/1.1 5"));
                assert!(response.1.contains("Content-Length:"));
            }
        }
    }
}

pub async fn send_response(
    socket: &mut UnixStream,
    response_parts: HttpResponse,
    logger: Option<&AsyncLogger>,
) {
    let (status, headers, body) = response_parts;
    for part in [status.as_bytes(), headers.as_bytes(), body.as_slice()] {
        if let Err(error) = socket.write_all(part).await {
            log_message(logger, format!("Failed to write response: {error}"))
                .await;
            return;
        }
    }
}

pub async fn read_socket(
    socket: &mut UnixStream,
) -> Result<String, std::io::Error> {
    let mut buf = [0; 8192];
    let count = socket.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..count]).to_string())
}

async fn log_message(logger: Option<&AsyncLogger>, message: String) {
    if let Some(logger) = logger {
        logger.log(&message).await;
    } else {
        eprintln!("{message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn rejects_content_length_and_ambiguous_framing() {
        for request in [
            b"GET /one HTTP/1.1\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"HEAD /one HTTP/1.1\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"GET /one HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".as_slice(),
            b"GET /one HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
        ] {
            assert!(parse_http_request(request).is_err());
        }
    }

    #[tokio::test]
    async fn content_length_zero_cannot_turn_a_pipeline_into_two_requests() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;
        let (mut writer, reader) = UnixStream::pair().unwrap();
        writer
            .write_all(
                b"GET /one HTTP/1.1\r\nContent-Length: 0\r\n\r\nGET /two HTTP/1.1\r\n\r\n",
            )
            .await
            .unwrap();
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(read_http_request(&mut reader).await.is_err());
    }

    #[test]
    fn close_wins_across_all_connection_headers() {
        for headers in [
            "Connection: keep-alive\r\nConnection: close\r\n",
            "Connection: close\r\nConnection: keep-alive\r\n",
        ] {
            let request = parse_http_request(
                format!("GET / HTTP/1.1\r\n{headers}\r\n").as_bytes(),
            )
            .unwrap();
            assert!(!request.keep_alive());
        }
    }

    #[tokio::test]
    async fn framed_reader_handles_split_and_pipelined_requests() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let writer_task = tokio::spawn(async move {
            writer
                .write_all(b"GET /one HTTP/1.1\r\nHost: ex")
                .await
                .unwrap();
            tokio::task::yield_now().await;
            writer
                .write_all(b"ample\r\n\r\nGET /two HTTP/1.1\r\n\r\n")
                .await
                .unwrap();
        });
        let mut reader = tokio::io::BufReader::new(reader);
        let first = read_http_request(&mut reader).await.unwrap().unwrap();
        let second = read_http_request(&mut reader).await.unwrap().unwrap();
        writer_task.await.unwrap();
        assert_eq!(first.path, "/one");
        assert_eq!(first.header("host"), Some("example"));
        assert_eq!(second.path, "/two");
    }

    #[tokio::test]
    async fn framed_reader_caps_headers_and_can_timeout() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::UnixStream;
        let (mut writer, reader) = UnixStream::pair().unwrap();
        let writer_task = tokio::spawn(async move {
            let _ = writer
                .write_all(&vec![b'a'; MAX_REQUEST_HEADER_BYTES])
                .await;
        });
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(matches!(
            read_http_request(&mut reader).await,
            Err(RequestReadError::HeaderTooLarge)
        ));
        writer_task.await.unwrap();

        let (_writer, reader) = UnixStream::pair().unwrap();
        let mut reader = tokio::io::BufReader::new(reader);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                read_http_request(&mut reader)
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn ranges_head_and_pdf_headers_are_correct() {
        assert_eq!(guess_mime_type("document.pdf"), "application/pdf");
        let get = parse_http_request(
            b"GET /file.pdf HTTP/1.1\r\nRange: bytes=1-3\r\n\r\n",
        )
        .unwrap();
        let base = (
            "HTTP/1.1 200 OK\r\n".to_string(),
            "Content-Length: 6\r\nContent-Type: application/pdf\r\n\r\n"
                .to_string(),
            b"abcdef".to_vec(),
        );
        let ranged = finalize_response(base.clone(), &get);
        assert_eq!(ranged.0, "HTTP/1.1 206 Partial Content\r\n");
        assert_eq!(ranged.2, b"bcd");
        assert!(ranged.1.contains("Content-Range: bytes 1-3/6"));
        assert!(ranged.1.contains("Accept-Ranges: bytes"));

        let head = parse_http_request(
            b"HEAD /file.pdf HTTP/1.1\r\nRange: bytes=1-3\r\n\r\n",
        )
        .unwrap();
        let head_response = finalize_response(base, &head);
        assert!(head_response.2.is_empty());
        assert!(head_response.1.contains("Content-Length: 3"));

        let unsat = parse_http_request(
            b"GET /file.pdf HTTP/1.1\r\nRange: bytes=99-100\r\n\r\n",
        )
        .unwrap();
        let unsat_response = finalize_response(
            (
                "HTTP/1.1 200 OK\r\n".to_string(),
                "Content-Length: 6\r\n\r\n".to_string(),
                b"abcdef".to_vec(),
            ),
            &unsat,
        );
        assert!(unsat_response.0.starts_with("HTTP/1.1 416"));
        assert!(unsat_response.1.contains("Content-Range: bytes */6"));
    }

    #[test]
    fn document_root_is_single_secure_root() {
        let root = std::env::temp_dir()
            .join(format!("ronfire-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("file.pdf"), b"pdf").unwrap();
        std::fs::write(root.join("app.log"), b"secret").unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let document_root = DocumentRoot::new(&root, None).unwrap();
        assert!(document_root.resolve("/file.pdf").is_some());
        assert!(document_root.resolve("/app.log").is_none());
        assert!(document_root.resolve("/.git/config").is_none());
        let _ = std::fs::remove_dir_all(root);
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
