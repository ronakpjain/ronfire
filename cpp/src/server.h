/** @file server.h @brief Startup and connection-task composition. */

#pragma once

#include <string>
#include <vector>

#include "runtime/task.h"

namespace ronfire {

/**
 * @brief Runs the Unix-socket server.
 *
 * Builds the plugin registry, loads routes, establishes the document root,
 * and accepts connections forever. Startup failures are thrown as
 * std::exception (main reports them and exits non-zero).
 *
 * @param args Process arguments including the program name.
 */
runtime::Task<void> run(std::vector<std::string> args);

}  // namespace ronfire
