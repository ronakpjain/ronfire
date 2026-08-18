//! HTTP request parsing, framing, range handling, and response finalization.

use std::fmt;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncReadExt};

/// Complete HTTP response parts: status line, headers, and body.
pub type HttpResponse = (String, String, Vec<u8>);

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

#[cfg(test)]
mod tests {
    use super::*;

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
            .write_all(b"GET /one HTTP/1.1\r\nContent-Length: 0\r\n\r\nGET /two HTTP/1.1\r\n\r\n")
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
                Duration::from_millis(100),
                read_http_request(&mut reader)
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn ranges_head_and_pdf_headers_are_correct() {
        assert_eq!(
            super::super::static_files::guess_mime_type("document.pdf"),
            "application/pdf"
        );
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
}
