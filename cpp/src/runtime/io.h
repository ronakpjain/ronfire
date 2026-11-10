// Non-blocking fd IO awaitables and small helpers.
//
// All sockets use O_NONBLOCK fds. Awaitables wait for readiness (or a
// deadline) and the caller performs the syscall afterwards; helpers loop over
// partial reads/writes until they complete, hit EOF, fail, or pass a single
// absolute deadline. One deadline covers the whole helper call, matching
// tokio::time::timeout around a whole request read in the Rust server.

#pragma once

#include <poll.h>

#include <chrono>
#include <cstddef>
#include <coroutine>
#include <memory>
#include <optional>
#include <utility>

#include "runtime/loop.h"
#include "runtime/task.h"

namespace ronfire::runtime {

// Error returned by single-shot IO helpers. timed_out marks deadline expiry;
// otherwise err is the errno from the failed syscall.
struct IoError {
  int err = 0;
  bool timed_out = false;
};

// Minimal expected: either a value or an IoError.
template <typename T>
class Expected {
 public:
  static Expected ok(T value) {
    Expected result;
    result.value_ = value;
    return result;
  }
  static Expected fail(IoError error) {
    Expected result;
    result.error_ = error;
    return result;
  }

  bool has_value() const noexcept { return value_.has_value(); }
  const T& value() const& { return value_.value(); }
  T& value() & { return value_.value(); }
  T&& value() && { return std::move(value_).value(); }
  IoError error() const { return error_; }

 private:
  std::optional<T> value_{};
  IoError error_{};
};

// Waits until fd has the requested readiness or the deadline passes.
// await_resume() returns true when the deadline expired (timed out).
struct ReadyAwaitable {
  int fd;
  short events;
  std::optional<TimePoint> deadline;
  std::shared_ptr<WaiterState> state = std::make_shared<WaiterState>();

  bool await_ready() const noexcept { return false; }
  void await_suspend(std::coroutine_handle<> h) {
    EventLoop::current()->add_waiter(fd, events, h, deadline, state);
  }
  bool await_resume() const { return state->timed_out; }
};

struct SleepAwaitable {
  std::chrono::steady_clock::duration duration;
  std::shared_ptr<WaiterState> state = std::make_shared<WaiterState>();

  bool await_ready() const noexcept { return false; }
  void await_suspend(std::coroutine_handle<> h) {
    EventLoop::current()->add_waiter(-1, 0, h, Clock::now() + duration, state);
  }
  bool await_resume() const { return state->timed_out; }
};

// Places fd in non-blocking mode (O_NONBLOCK).
void set_nonblocking(int fd);

// Reads once (may return short). Returns 0 on EOF.
Task<Expected<ssize_t>> read_once(int fd, char* buffer, std::size_t capacity,
                                  std::optional<TimePoint> deadline);

// Writes everything or fails. Returns ok(true) only when all bytes are sent.
Task<Expected<bool>> write_all(int fd, const char* buffer, std::size_t length,
                               std::optional<TimePoint> deadline);

// Resolves after the given delay (implemented as a deadline waiter).
Task<void> sleep(std::chrono::steady_clock::duration duration);

}  // namespace ronfire::runtime
