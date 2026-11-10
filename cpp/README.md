# ronfire (C++ rewrite)

A dependency-free C++20 rewrite of the Rust `ronfire` Unix-socket HTTP server.
This tree is built incrementally, one commit per feature, mirroring the Rust
module layout under `../src`:

```text
src/main.cpp                 entrypoint
src/runtime/                 hand-written coroutine event loop (no libuv/asio)
src/cli.*                    CLI argument parsing
src/http.*                   strict HTTP parsing, framing, ranges, finalization
src/static_files.*           secure document root and static responses
src/transport.*              Unix socket creation, writes, logging
src/server.*                 startup and connection-task composition
src/plugins.*                compiled plugin registry, config, dispatch, cache
src/plugins/proxy.*          fixed-target proxy plugin
```

No third-party dependencies: only the C++ standard library and POSIX sockets.
Build with CMake:

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build
ctest --test-dir cpp/build
```
