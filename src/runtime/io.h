/** @file io.h @brief Non-blocking fd IO awaitables and helpers. */

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

/** @brief IO error; timed_out marks deadline expiry, else errno. */
struct IoError {
  int err = 0;
  bool timed_out = false;
};

/** @brief Value-or-error result. @tparam T Value, @tparam E Error. */
template <typename T, typename E = IoError>
class Expected {
 public:
  /** @brief Builds a success. */
  static Expected ok(T value) {
    Expected result;
    result.value_ = value;
    return result;
  }

  /** @brief Builds a failure. */
  static Expected fail(E error) {
    Expected result;
    result.error_ = std::move(error);
    return result;
  }

  /** @brief True when holding a value. */
  bool has_value() const noexcept { return value_.has_value(); }

  /** @brief Unchecked value access (undefined when failed). */
  const T& value() const& { return value_.value(); }
  T& value() & { return value_.value(); }
  T&& value() && { return std::move(value_).value(); }

  /** @brief Unchecked error access (undefined on success). */
  E error() const { return error_; }

 private:
  std::optional<T> value_{};
  E error_{};
};

/** @brief Waits for fd readiness or deadline; resumes true on timeout. */
struct ReadyAwaitable {
  int fd;     ///< File descriptor to watch.
  short events; ///< poll() events to wait for.
  std::optional<TimePoint> deadline; ///< Absolute deadline, if any.
  std::shared_ptr<WaiterState> state = std::make_shared<WaiterState>();

  bool await_ready() const noexcept { return false; }

  void await_suspend(std::coroutine_handle<> h) {
    EventLoop::current()->add_waiter(fd, events, h, deadline, state);
  }

  /** @brief True on deadline expiry. */
  bool await_resume() const { return state->timed_out; }
};

/** @brief Deadline-only waiter for sleep(). */
struct SleepAwaitable {
  std::chrono::steady_clock::duration duration; ///< Delay to wait.
  std::shared_ptr<WaiterState> state = std::make_shared<WaiterState>();

  bool await_ready() const noexcept { return false; }

  void await_suspend(std::coroutine_handle<> h) {
    EventLoop::current()->add_waiter(-1, 0, h, Clock::now() + duration, state);
  }

  /** @brief True when the timer fired. */
  bool await_resume() const { return state->timed_out; }
};

/** @brief Makes fd non-blocking. */
void set_nonblocking(int fd);

/** @brief Reads once (short ok, 0 = EOF). */
Task<Expected<ssize_t>> read_once(int fd, char* buffer, std::size_t capacity,
                                  std::optional<TimePoint> deadline);

/** @brief Writes all bytes or fails. */
Task<Expected<bool>> write_all(int fd, const char* buffer, std::size_t length,
                               std::optional<TimePoint> deadline);

/** @brief Sleeps for a duration. */
Task<void> sleep(std::chrono::steady_clock::duration duration);

}  // namespace ronfire::runtime
