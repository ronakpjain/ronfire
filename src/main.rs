//! `ronfire` server entrypoint.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ronfire::server::run(std::env::args()).await
}
