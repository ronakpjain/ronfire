/** @file transport.cpp @brief Transport implementation (see transport.h). */

#include "transport.h"

#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <utility>

namespace ronfire {

void AsyncLogger::log(const std::string& message) const {
  std::lock_guard<std::mutex> guard(mutex_);
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
    const int fd = ::accept(listener_fd, nullptr, nullptr);
    if (fd >= 0) {
      runtime::set_nonblocking(fd);
      co_return Result::ok(fd);
    }
    const int error = errno;
    if (error == EINTR) {
      continue;
    }
    if (error == EAGAIN || error == EWOULDBLOCK) {
      const bool timed_out =
          co_await runtime::ReadyAwaitable{listener_fd, POLLIN, deadline};
      if (timed_out) {
        co_return Result::fail(runtime::IoError{0, true});
      }
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
  // One writev per attempt sends status, headers, and body together.
  std::size_t done[3] = {0, 0, 0};
  const std::size_t totals[3] = {response.status.size(),
                                 response.headers.size(),
                                 response.body.size()};
  const void* bases[3] = {response.status.data(), response.headers.data(),
                          response.body.data()};
  while (done[0] < totals[0] || done[1] < totals[1] || done[2] < totals[2]) {
    struct iovec parts[3];
    int which[3];
    int count = 0;
    for (int k = 0; k < 3; ++k) {
      if (done[k] < totals[k]) {
        parts[count].iov_base = const_cast<char*>(
            static_cast<const char*>(bases[k]) + done[k]);
        parts[count].iov_len = totals[k] - done[k];
        which[count] = k;
        ++count;
      }
    }
    const ssize_t sent = ::writev(fd, parts, count);
    if (sent > 0) {
      std::size_t left = static_cast<std::size_t>(sent);
      for (int i = 0; i < count; ++i) {
        const std::size_t chunk = parts[i].iov_len;
        if (left < chunk) {
          done[which[i]] += left;
          break;
        }
        done[which[i]] += chunk;
        left -= chunk;
      }
      continue;
    }
    const int error = errno;
    if (error == EINTR) {
      continue;
    }
    if (error == EAGAIN || error == EWOULDBLOCK) {
      const bool timed_out =
          co_await runtime::ReadyAwaitable{fd, POLLOUT, std::nullopt};
      if (timed_out) {
        co_return Result::fail(runtime::IoError{0, true});
      }
      continue;
    }
    report(std::string("Failed to write response: ") + std::strerror(error));
    co_return Result::fail(runtime::IoError{error, false});
  }
  co_return Result::ok(true);
}

}  // namespace ronfire
