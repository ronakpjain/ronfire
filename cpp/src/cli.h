// Command-line argument parsing for the ronfire server.
//
// Keeps the historical positional socket argument and the explicit --config /
// --root paths used at startup. Syntax validation only; filesystem policy is
// applied during startup. Error strings match the Rust implementation.

#pragma once

#include <string>
#include <vector>

#include "runtime/io.h"

namespace ronfire {

struct Args {
  std::string socket_path = "/tmp/ronfire.sock";
  std::string config_path = "ronfire.conf";
  bool config_explicit = false;
  std::string root_path = ".";
};

// args includes the program name at index 0 (like std::env::args()).
runtime::Expected<Args, std::string> parse_args(const std::vector<std::string>& args);

}  // namespace ronfire
