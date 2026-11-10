# Binary only; tests run in GitHub Actions CI.
FROM alpine:latest AS builder
RUN apk add --no-cache build-base cmake openssl-dev
WORKDIR /build
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF && \
    cmake --build build

# Runtime stage: binary + libstdc++ + OpenSSL (proxy TLS).
FROM alpine:latest
RUN apk add --no-cache libstdc++ libssl3 libcrypto3
WORKDIR /app
COPY --from=builder /build/build/ronfire /usr/local/bin/ronfire
ENTRYPOINT ["ronfire"]
