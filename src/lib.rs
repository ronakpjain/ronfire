#![warn(missing_docs)]

//! A small, Unix-socket HTTP server with secure static files and compiled-in plugins.
//!
//! A request enters through [`http`], which strictly parses and frames one
//! HTTP/1.0 or HTTP/1.1 request. [`server`] then checks the exact-route
//! [`plugins`] registry before resolving a path beneath [`static_files::DocumentRoot`].
//! [`http::finalize_response`] applies range and `HEAD` semantics, and
//! [`transport`] writes the buffered response and serializes request logging.
//!
//! Plugin implementations live separately under `src/plugins`; configuration
//! can only instantiate plugins that were compiled and registered in the
//! binary. The public [`plugins`] traits are the extension seam. See the
//! [plugin guide](https://github.com/ronakpjain/ronfire/blob/master/docs/plugins.md)
//! for the trusted plugin model and a fork-based implementation walkthrough.
//!
//! The modules are also available directly: [`cli`] parses process arguments,
//! [`http`] owns protocol parsing, [`plugins`] owns registry/configuration and
//! dispatch, [`server`] composes the runtime, [`static_files`] owns document
//! root security, and [`transport`] owns Unix-socket I/O.

pub mod cli;
pub mod http;
pub mod plugins;
pub mod server;
pub mod static_files;
pub mod transport;

pub use cli::parse_args;
pub use http::{
    ByteRangeSpec, HttpRequest, HttpResponse, MAX_REQUEST_HEADER_BYTES,
    REQUEST_IDLE_TIMEOUT, RangeParseError, RequestRange, RequestReadError,
    finalize_response, parse_http_request, parse_range_header,
    read_http_request,
};
#[cfg(feature = "proxy")]
pub use plugins::proxy;
pub use plugins::{
    ConfigError, DispatchFuture, PluginFactory, PluginHandler, PluginRegistry,
    PluginRequest, RouteConfig, TtlCache, dispatch_request,
};
pub use static_files::{
    DocumentRoot, generate_response, parse_request, parse_request_path,
};
pub use transport::{AsyncLogger, create_socket, read_socket, send_response};
