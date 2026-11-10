/** @file transport.cpp @brief Transport implementation (see transport.h). */

#include "transport.h"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <utility>

namespace ronfire {

void AsyncLogger::log(const std::string& message) const {
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
  std::fprintf(stderr, "[%lld] %s\n", static_cast<long long>(seconds),
               message.c_str());
  std::fflush(stderr);
}

runtime::Expected<int> create_socket(const std::string& socket_path) {
  ::unlink(socket_path.c_str());
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    return runtime::Expected<int>::fail(runtime::IoError{errno, false});
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  const std::size_t needed = socket_path.size() + 1;
  if (needed > sizeof(address.sun_path)) {
    ::close(fd);
    return runtime::Expected<int>::fail(runtime::IoError{ENAMETOOLONG, false});
  }
  socket_path.copy(address.sun_path, socket_path.size());
  address.sun_path[socket_path.size()] = '\0';
  if (::bind(fd, reinterpret_cast<const sockaddr*>(&address),
             sizeof(address)) != 0) {
    const int error = errno;
    ::close(fd);
    return runtime::Expected<int>::fail(runtime::IoError{error, false});
  }
  if (::listen(fd, SOMAXCONN) != 0) {
    const int error = errno;
    ::close(fd);
    return runtime::Expected<int>::fail(runtime::IoError{error, false});
  }
  runtime::set_nonblocking(fd);
  return runtime::Expected<int>::ok(fd);
}

runtime::Task<runtime::Expected<int>> accept_once(
    int listener_fd, std::optional<runtime::TimePoint> deadline) {
  using Result = runtime::Expected<int>;
  for (;;) {
    const bool timed_out =
        co_await runtime::ReadyAwaitable{listener_fd, POLLIN, deadline};
    if (timed_out) {
      co_return Result::fail(runtime::IoError{0, true});
    }
    const int fd = ::accept(listener_fd, nullptr, nullptr);
    if (fd >= 0) {
      runtime::set_nonblocking(fd);
      co_return Result::ok(fd);
    }
    const int error = errno;
    if (error == EINTR || error == EAGAIN || error == EWOULDBLOCK) {
      continue;
    }
    co_return Result::fail(runtime::IoError{error, false});
  }
}

runtime::Task<runtime::Expected<bool>> send_response(int fd,
                                                      const HttpResponse& response,
                                                      const AsyncLogger* logger) {
  using Result = runtime::Expected<bool>;
  const auto report = [logger](const std::string& message) {
    if (logger != nullptr) {
      logger->log(message);
    } else {
      std::fprintf(stderr, "%s\n", message.c_str());
    }
  };
  auto fail = [report](const runtime::IoError& error) -> Result {
    report(std::string("Failed to write response: ") +
           std::strerror(error.err));
    return Result::fail(error);
  };
  auto first = co_await runtime::write_all(
      fd, response.status.data(), response.status.size(), std::nullopt);
  if (!first.has_value()) {
    co_return fail(first.error());
  }
  auto second = co_await runtime::write_all(
      fd, response.headers.data(), response.headers.size(), std::nullopt);
  if (!second.has_value()) {
    co_return fail(second.error());
  }
  const std::string body(response.body.begin(), response.body.end());
  auto third = co_await runtime::write_all(fd, body.data(), body.size(),
                                           std::nullopt);
  if (!third.has_value()) {
    co_return fail(third.error());
  }
  co_return Result::ok(true);
}

}  // namespace ronfire
