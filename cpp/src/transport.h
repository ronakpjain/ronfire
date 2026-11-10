/** @file transport.h @brief Unix socket transport + logger. */

#pragma once

#include <cstddef>
#include <optional>
#include <string>

#include "http.h"
#include "runtime/io.h"
#include "runtime/loop.h"
#include "runtime/task.h"

namespace ronfire {

/** @brief Timestamped stderr logger. */
class AsyncLogger {
 public:
  /** @brief Writes one timestamped line to stderr. */
  void log(const std::string& message) const;
};

/** @brief Binds a Unix listener, replacing any existing socket file. */
runtime::Expected<int> create_socket(const std::string& socket_path);

/** @brief Accepts one connection (non-blocking). */
runtime::Task<runtime::Expected<int>> accept_once(
    int listener_fd, std::optional<runtime::TimePoint> deadline);

/** @brief Writes status, headers, body in order. */
runtime::Task<runtime::Expected<bool>> send_response(
    int fd, const HttpResponse& response,
    const AsyncLogger* logger = nullptr);

}  // namespace ronfire
