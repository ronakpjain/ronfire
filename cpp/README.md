# ronfire (C++)

C++ implementation of `ronfire`. No third-party deps in the server (C++20 + POSIX only).

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build
ctest --test-dir cpp/build
```

Layout: `src/main.cpp`, `src/runtime/` (coroutine event loop), `src/cli.*`,
`src/http.*`, `src/static_files.*`, `src/transport.*`, `src/server.*`,
`src/plugins.*`, `src/plugins/proxy.*`. Tests use system GoogleTest (test-only).
