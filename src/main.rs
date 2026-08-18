//! `ronfire`'s Unix-socket HTTP server entrypoint. Startup assembles the
//! compiled plugin registry, validates configuration, and serves static and
//! plugin-owned responses without exposing the configuration root by default.

use ronfire::{
    AsyncLogger, DocumentRoot, PluginRegistry, REQUEST_IDLE_TIMEOUT,
    RequestReadError, RouteConfig, TtlCache, dispatch_request,
    finalize_response, generate_response, read_http_request,
};
use std::env;
use std::path::PathBuf;
use tokio::io::BufReader;
use tokio::net::UnixStream;

fn parse_args(
    args: impl IntoIterator<Item = String>,
) -> Result<(String, PathBuf, bool, PathBuf), String> {
    let mut socket_path = None;
    let mut config_path = PathBuf::from("ronfire.conf");
    let mut config_explicit = false;
    let mut root_path = PathBuf::from(".");
    let mut arguments = args.into_iter().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--config" {
            config_path = PathBuf::from(
                arguments
                    .next()
                    .ok_or_else(|| "--config requires a path".to_string())?,
            );
            config_explicit = true;
        } else if let Some(path) = argument.strip_prefix("--config=") {
            if path.is_empty() {
                return Err("--config requires a path".to_string());
            }
            config_path = PathBuf::from(path);
            config_explicit = true;
        } else if argument == "--root" {
            root_path = PathBuf::from(
                arguments
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?,
            );
        } else if let Some(path) = argument.strip_prefix("--root=") {
            if path.is_empty() {
                return Err("--root requires a path".to_string());
            }
            root_path = PathBuf::from(path);
        } else if argument.starts_with('-') {
            return Err(format!("unknown option: {argument}"));
        } else if socket_path.replace(argument).is_some() {
            return Err("only one socket path may be specified".to_string());
        }
    }
    Ok((
        socket_path.unwrap_or_else(|| "/tmp/ronfire.sock".to_string()),
        config_path,
        config_explicit,
        root_path,
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (socket_path, config_path, config_explicit, root_path) =
        parse_args(env::args()).map_err(std::io::Error::other)?;
    let registry = PluginRegistry::with_builtins()?;
    let routes = RouteConfig::load(&config_path, &registry, !config_explicit)?;
    let denied_config = std::fs::canonicalize(&config_path).ok();
    let document_root =
        DocumentRoot::new(&root_path, denied_config.as_deref())?;
    let logger = AsyncLogger::new();
    let listener = ronfire::create_socket(socket_path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("could not create ronfire Unix socket: {error}"),
        )
    })?;
    let cache = TtlCache::new();

    loop {
        let (socket, _) = listener.accept().await?;
        let logger = logger.clone();
        let routes = routes.clone();
        let cache = cache.clone();
        let document_root = document_root.clone();

        tokio::spawn(async move {
            let mut reader = BufReader::new(socket);
            loop {
                let request = match tokio::time::timeout(
                    REQUEST_IDLE_TIMEOUT,
                    read_http_request(&mut reader),
                )
                .await
                {
                    Ok(Ok(Some(request))) => request,
                    Ok(Ok(None)) => break,
                    Ok(Err(error)) => {
                        let (status, body) = match error {
                            RequestReadError::HeaderTooLarge => (
                                "HTTP/1.1 431 Request Header Fields Too Large\r\n",
                                "<h1>431 Request Header Fields Too Large</h1>",
                            ),
                            RequestReadError::Malformed(message) => {
                                logger
                                    .log(&format!(
                                        "Malformed request: {message}"
                                    ))
                                    .await;
                                (
                                    "HTTP/1.1 400 Bad Request\r\n",
                                    "<h1>400 Bad Request</h1>",
                                )
                            }
                            RequestReadError::Io(error) => {
                                logger
                                    .log(&format!(
                                        "Request read failed: {error}"
                                    ))
                                    .await;
                                break;
                            }
                        };
                        send_simple_response(reader.get_mut(), status, body)
                            .await;
                        break;
                    }
                    Err(_) => {
                        send_simple_response(
                            reader.get_mut(),
                            "HTTP/1.1 408 Request Timeout\r\n",
                            "<h1>408 Request Timeout</h1>",
                        )
                        .await;
                        break;
                    }
                };

                let keep_alive = request.keep_alive();
                let mut response = if request.method != "GET"
                    && request.method != "HEAD"
                {
                    (
                        "HTTP/1.1 405 Method Not Allowed\r\n".to_string(),
                        "Allow: GET, HEAD\r\nContent-Length: 0\r\n\r\n"
                            .to_string(),
                        Vec::new(),
                    )
                } else if let Some(response) =
                    dispatch_request(&routes, &request, &cache).await
                {
                    response
                } else if let Some(full_path) =
                    document_root.resolve(&request.path)
                {
                    finalize_response(
                        generate_response(&full_path.to_string_lossy()),
                        &request,
                    )
                } else {
                    let body = b"<h1>404 Not Found</h1>".to_vec();
                    finalize_response(
                        (
                            "HTTP/1.1 404 Not Found\r\n".to_string(),
                            format!(
                                "Content-Length: {}\r\nContent-Type: text/html\r\n\r\n",
                                body.len()
                            ),
                            body,
                        ),
                        &request,
                    )
                };

                let connection_header = if keep_alive {
                    "Connection: keep-alive\r\n"
                } else {
                    "Connection: close\r\n"
                };
                response.1 = format!("{connection_header}{}", response.1);
                ronfire::send_response(
                    reader.get_mut(),
                    response,
                    Some(&logger),
                )
                .await;
                if !keep_alive {
                    break;
                }
            }
        });
    }
}

async fn send_simple_response(
    socket: &mut UnixStream,
    status: &str,
    body: &str,
) {
    let body = body.as_bytes().to_vec();
    ronfire::send_response(
        socket,
        (
            status.to_string(),
            format!(
                "Connection: close\r\nContent-Length: {}\r\nContent-Type: text/html\r\n\r\n",
                body.len()
            ),
            body,
        ),
        None,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    #[test]
    fn keeps_positional_socket_and_accepts_config_and_root() {
        assert_eq!(
            parse_args([
                "ronfire".to_string(),
                "/tmp/test.sock".to_string(),
                "--config".to_string(),
                "/etc/ronfire.conf".to_string(),
                "--root".to_string(),
                "/srv/site".to_string(),
            ])
            .unwrap(),
            (
                "/tmp/test.sock".to_string(),
                "/etc/ronfire.conf".into(),
                true,
                "/srv/site".into(),
            )
        );
    }

    #[test]
    fn default_config_and_root_are_implicit() {
        assert_eq!(
            parse_args(["ronfire".to_string()]).unwrap(),
            (
                "/tmp/ronfire.sock".to_string(),
                "ronfire.conf".into(),
                false,
                ".".into(),
            )
        );
    }
}
