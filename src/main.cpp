/**
 * @file main.cpp
 * @brief Entry point for the C++ ronfire Unix-socket server.
 *
 * Ignores SIGPIPE (writes to a closed socket must fail, not kill the
 * process, matching the Rust runtime) and runs the server on the event loop.
 */

#include <csignal>
#include <cstdio>
#include <string>
#include <vector>

#include "runtime/loop.h"
#include "server.h"

int main(int argc, char** argv) {
  std::signal(SIGPIPE, SIG_IGN);
  std::vector<std::string> args;
  for (int i = 0; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }
  try {
    ronfire::runtime::block_on(ronfire::run(args));
    return 0;
  } catch (const std::exception& error) {
    std::fprintf(stderr, "Error: %s\n", error.what());
    return 1;
  }
}
