# Stage 1: Build static binary
FROM rust:latest AS builder
WORKDIR /build
COPY . .

# ring needs a C compiler and linker for the musl target. musl-tools provides
# musl-gcc; explicitly select it so build scripts do not look for the missing
# x86_64-linux-musl-gcc name.
RUN apt-get update && \
    apt-get install -y --no-install-recommends musl-tools && \
    rm -rf /var/lib/apt/lists/*
ENV CC_x86_64_unknown_linux_musl=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc

# Build for musl to get a static binary
RUN rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --target x86_64-unknown-linux-musl

# Stage 2: Minimal runtime
FROM alpine:latest
WORKDIR /app

# rustls uses reqwest's bundled webpki roots; no external fetch utility is required.
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ronfire /usr/local/bin/ronfire

ENTRYPOINT ["ronfire"]
