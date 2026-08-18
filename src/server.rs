//! Server composition: CLI, configuration, static files, plugins, and transport.

use tokio::io::BufReader;
use tokio::net::UnixStream;

use crate::cli::parse_args;
use crate::http::{
    REQUEST_IDLE_TIMEOUT, RequestReadError, finalize_response,
    read_http_request,
};
use crate::plugins::{PluginRegistry, RouteConfig, TtlCache, dispatch_request};
use crate::static_files::{DocumentRoot, generate_response};
use crate::transport::{AsyncLogger, create_socket, send_response};

/// Runs the Unix-socket server with the supplied process arguments.
pub async fn run(
    args: impl IntoIterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (socket_path, config_path, config_explicit, root_path) =
        parse_args(args).map_err(std::io::Error::other)?;
    let registry = PluginRegistry::with_builtins()?;
    let routes = RouteConfig::load(&config_path, &registry, !config_explicit)?;
    let denied_config = std::fs::canonicalize(&config_path).ok();
    let document_root =
        DocumentRoot::new(&root_path, denied_config.as_deref())?;
    let logger = AsyncLogger::new();
    let listener = create_socket(socket_path).map_err(|error| {
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
                send_response(reader.get_mut(), response, Some(&logger)).await;
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
    send_response(
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
