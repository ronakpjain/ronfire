//! Public module and compatibility facade for ronfire.
//!
//! The implementation is organized by ownership while these re-exports keep
//! the historical root-level request, static-file, plugin, and transport APIs.

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
