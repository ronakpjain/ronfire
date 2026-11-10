# Build + test stage.
FROM alpine:latest AS builder
RUN apk add --no-cache build-base cmake
WORKDIR /build
COPY . .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build && \
    ctest --test-dir build --output-on-failure

# Runtime stage: binary + libstdc++ only (server itself has no deps).
FROM alpine:latest
RUN apk add --no-cache libstdc++
WORKDIR /app
COPY --from=builder /build/build/ronfire /usr/local/bin/ronfire
ENTRYPOINT ["ronfire"]
