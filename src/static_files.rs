//! Secure document-root resolution and static response generation.

use std::fs;
use std::path::{Path, PathBuf};

use crate::http::{HttpResponse, parse_http_request};
use crate::transport::{AsyncLogger, log_message};

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

/// Generates a successful static response, or a local 404 response on read failure.
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

pub(crate) fn guess_mime_type(path: &str) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
