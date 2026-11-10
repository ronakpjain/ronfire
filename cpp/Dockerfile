# Build + test stage.
FROM alpine:latest AS builder
RUN apk add --no-cache build-base cmake
WORKDIR /build
COPY ./cpp ./cpp
RUN cmake -S cpp -B cpp/build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build cpp/build && \
    ctest --test-dir cpp/build --output-on-failure

# Runtime stage: binary + libstdc++ only (server itself has no deps).
FROM alpine:latest
RUN apk add --no-cache libstdc++
WORKDIR /app
COPY --from=builder /build/cpp/build/ronfire /usr/local/bin/ronfire
ENTRYPOINT ["ronfire"]
