/**
 * @file cli.h
 * @brief Command-line argument parsing for the ronfire server.
 *
 * Keeps the historical positional socket argument and the explicit --config /
 * --root paths used at startup. Syntax validation only; filesystem policy is
 * applied during startup. Error strings match the Rust implementation.
 */

#pragma once

#include <string>
#include <vector>

#include "runtime/io.h"

namespace ronfire {

/**
 * @brief Parsed process arguments with the historical defaults.
 */
struct Args {
  std::string socket_path = "/tmp/ronfire.sock"; ///< Unix socket to bind.
  std::string config_path = "ronfire.conf";      ///< Config file path.
  bool config_explicit = false;                  ///< True when --config given.
  std::string root_path = ".";                   ///< Document root.
};

/**
 * @brief Parses process arguments.
 *
 * @param args Arguments including the program name at index 0.
 * @return The parsed args, or the exact Rust error string.
 */
runtime::Expected<Args, std::string> parse_args(
    const std::vector<std::string>& args);

}  // namespace ronfire
