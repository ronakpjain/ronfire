//! Unix-socket transport and serialized logging helpers.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::http::HttpResponse;

/// A small serialized stderr logger suitable for concurrent connection tasks.
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

/// Writes a complete response to a Unix stream.
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

/// Legacy helper that reads one chunk from a Unix stream as lossy UTF-8.
pub async fn read_socket(
    socket: &mut UnixStream,
) -> Result<String, std::io::Error> {
    let mut buf = [0; 8192];
    let count = socket.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..count]).to_string())
}

pub(crate) async fn log_message(logger: Option<&AsyncLogger>, message: String) {
    if let Some(logger) = logger {
        logger.log(&message).await;
    } else {
        eprintln!("{message}");
    }
}
