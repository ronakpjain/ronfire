/** @file cli.h @brief CLI argument parsing. */

#pragma once

#include <string>
#include <vector>

#include "runtime/io.h"

namespace ronfire {

/** @brief Parsed args with historical defaults. */
struct Args {
  std::string socket_path = "/tmp/ronfire.sock"; ///< Unix socket to bind.
  std::string config_path = "ronfire.conf";      ///< Config file path.
  bool config_explicit = false;                  ///< True when --config given.
  std::string root_path = ".";                   ///< Document root.
};

/** @brief Parses args (index 0 = program name). */
runtime::Expected<Args, std::string> parse_args(
    const std::vector<std::string>& args);

}  // namespace ronfire
