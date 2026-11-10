// Binary entrypoint for the C++ ronfire Unix-socket server.
//
// The server modules are added incrementally; this stub establishes the process
// conventions that every later commit keeps: ignore SIGPIPE (writes to a closed
// socket must fail, not kill the process, matching the Rust runtime) and talk
// only over Unix sockets, never TCP.

#include <csignal>
#include <iostream>

int main() {
  std::signal(SIGPIPE, SIG_IGN);
  std::cout << "ronfire - server not yet implemented\n";
  return 0;
}
