/** @file io.cpp @brief Implementation. */

// IO helper implementations. See io.h for semantics.

#include "runtime/io.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <utility>

namespace ronfire::runtime {

void set_nonblocking(int fd) {
  const int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags >= 0) {
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  }
}

Task<Expected<ssize_t>> read_once(int fd, char* buffer, std::size_t capacity,
                                  std::optional<TimePoint> deadline) {
  for (;;) {
    // Try first: data is usually already buffered, avoiding a poll cycle.
    const ssize_t n = ::read(fd, buffer, capacity);
    if (n >= 0) {
      co_return Expected<ssize_t>::ok(n);
    }
    const int err = errno;
    if (err == EINTR) {
      continue;
    }
    if (err == EAGAIN || err == EWOULDBLOCK) {
      const bool timed_out = co_await ReadyAwaitable{fd, POLLIN, deadline};
      if (timed_out) {
        co_return Expected<ssize_t>::fail(IoError{0, true});
      }
      continue;
    }
    co_return Expected<ssize_t>::fail(IoError{err, false});
  }
}

Task<Expected<bool>> write_all(int fd, const char* buffer, std::size_t length,
                               std::optional<TimePoint> deadline) {
  std::size_t sent = 0;
  while (sent < length) {
    const ssize_t n = ::write(fd, buffer + sent, length - sent);
    if (n > 0) {
      sent += static_cast<std::size_t>(n);
      continue;
    }
    if (n == 0) {
      co_return Expected<bool>::fail(IoError{EIO, false});
    }
    const int err = errno;
    if (err == EINTR) {
      continue;
    }
    if (err == EAGAIN || err == EWOULDBLOCK) {
      const bool timed_out = co_await ReadyAwaitable{fd, POLLOUT, deadline};
      if (timed_out) {
        co_return Expected<bool>::fail(IoError{0, true});
      }
      continue;
    }
    co_return Expected<bool>::fail(IoError{err, false});
  }
  co_return Expected<bool>::ok(true);
}

Task<void> sleep(std::chrono::steady_clock::duration duration) {
  co_await SleepAwaitable{duration};
  co_return;
}

}  // namespace ronfire::runtime
