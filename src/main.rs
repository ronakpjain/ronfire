//! Binary entrypoint for the ronfire Unix-socket server.
//!
//! Argument parsing and runtime composition remain in [`ronfire::server`];
//! this binary only supplies process arguments to that library entrypoint.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ronfire::server::run(std::env::args()).await
}
