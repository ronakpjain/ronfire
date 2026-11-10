# Build + test stage.
FROM alpine:latest AS builder
RUN apk add --no-cache build-base cmake openssl-dev gtest
WORKDIR /build
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build && \
    ctest --test-dir build --output-on-failure

# Runtime stage: binary + libstdc++ + OpenSSL (proxy TLS).
FROM alpine:latest
RUN apk add --no-cache libstdc++ libssl3 libcrypto3
WORKDIR /app
COPY --from=builder /build/build/ronfire /usr/local/bin/ronfire
ENTRYPOINT ["ronfire"]
