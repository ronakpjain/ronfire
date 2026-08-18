# Stage 1: Build static binary
FROM rust:latest AS builder
WORKDIR /build
COPY . .

# Build for musl to get a static binary
RUN rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Minimal runtime
FROM alpine:latest
WORKDIR /app

# rustls uses reqwest's bundled webpki roots; no external fetch utility is required.
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ronfire /usr/local/bin/ronfire

ENTRYPOINT ["ronfire"]
