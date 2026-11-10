/**
 * @file io.h
 * @brief Non-blocking fd IO awaitables and small helpers.
 *
 * All sockets use O_NONBLOCK fds. Awaitables wait for readiness (or a
 * deadline) and the caller performs the syscall afterwards; helpers loop over
 * partial reads/writes until they complete, hit EOF, fail, or pass a single
 * absolute deadline. One deadline covers the whole helper call, matching
 * tokio::time::timeout around a whole request read in the Rust server.
 */

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

/**
 * @brief Error returned by single-shot IO helpers.
 *
 * timed_out marks deadline expiry; otherwise err is the errno from the failed
 * syscall.
 */
struct IoError {
  int err = 0;
  bool timed_out = false;
};

/**
 * @brief Minimal expected: either a value or an error E (IoError by default).
 *
 * @tparam T The success value type.
 * @tparam E The error type.
 */
template <typename T, typename E = IoError>
class Expected {
 public:
  /**
   * @brief Builds a successful expected.
   * @param value The success value.
   */
  static Expected ok(T value) {
    Expected result;
    result.value_ = value;
    return result;
  }

  /**
   * @brief Builds a failed expected.
   * @param error The error.
   */
  static Expected fail(E error) {
    Expected result;
    result.error_ = std::move(error);
    return result;
  }

  /**
   * @brief Reports whether this holds a value.
   * @return True on success.
   */
  bool has_value() const noexcept { return value_.has_value(); }

  /**
   * @brief Returns the value (unchecked). Undefined when failed.
   */
  const T& value() const& { return value_.value(); }

  /**
   * @brief Returns the value (unchecked). Undefined when failed.
   */
  T& value() & { return value_.value(); }

  /**
   * @brief Moves out the value (unchecked). Undefined when failed.
   */
  T&& value() && { return std::move(value_).value(); }

  /**
   * @brief Returns the error (unchecked). Undefined on success.
   */
  E error() const { return error_; }

 private:
  std::optional<T> value_{};
  E error_{};
};

/**
 * @brief Waits until fd has the requested readiness or the deadline passes.
 *
 * await_resume() returns true when the deadline expired (timed out).
 */
struct ReadyAwaitable {
  int fd;     ///< File descriptor to watch.
  short events; ///< poll() events to wait for.
  std::optional<TimePoint> deadline; ///< Absolute deadline, if any.
  std::shared_ptr<WaiterState> state = std::make_shared<WaiterState>();

  /**
   * @brief Always suspends; resume is driven by the event loop.
   */
  bool await_ready() const noexcept { return false; }

  /**
   * @brief Registers this awaitable and handle with the current loop.
   */
  void await_suspend(std::coroutine_handle<> h) {
    EventLoop::current()->add_waiter(fd, events, h, deadline, state);
  }

  /**
   * @brief Reports whether the waiter expired by deadline.
   * @return True on deadline expiry.
   */
  bool await_resume() const { return state->timed_out; }
};

/**
 * @brief Deadline-only waiter used to implement sleep().
 */
struct SleepAwaitable {
  std::chrono::steady_clock::duration duration; ///< Delay to wait.
  std::shared_ptr<WaiterState> state = std::make_shared<WaiterState>();

  /**
   * @brief Always suspends; resume is driven by the event loop.
   */
  bool await_ready() const noexcept { return false; }

  /**
   * @brief Registers the timer waiter with the current loop.
   */
  void await_suspend(std::coroutine_handle<> h) {
    EventLoop::current()->add_waiter(-1, 0, h, Clock::now() + duration, state);
  }

  /**
   * @brief Reports whether the timer fired (always true for sleep).
   * @return True when resumed by the event loop.
   */
  bool await_resume() const { return state->timed_out; }
};

/**
 * @brief Places fd in non-blocking mode (O_NONBLOCK).
 * @param fd File descriptor to make non-blocking.
 */
void set_nonblocking(int fd);

/**
 * @brief Reads once (may return short). Returns 0 on EOF.
 * @param fd Non-blocking fd to read from.
 * @param buffer Destination buffer.
 * @param capacity Maximum bytes to read.
 * @param deadline Absolute deadline, or std::nullopt for none.
 * @return Bytes read (0 on EOF), or the IO error/timeout.
 */
Task<Expected<ssize_t>> read_once(int fd, char* buffer, std::size_t capacity,
                                  std::optional<TimePoint> deadline);

/**
 * @brief Writes everything or fails.
 * @param fd Non-blocking fd to write to.
 * @param buffer Source buffer.
 * @param length Total bytes to write.
 * @param deadline Absolute deadline, or std::nullopt for none.
 * @return ok(true) only when all bytes are sent, or the IO error/timeout.
 */
Task<Expected<bool>> write_all(int fd, const char* buffer, std::size_t length,
                               std::optional<TimePoint> deadline);

/**
 * @brief Resolves after the given delay (implemented as a deadline waiter).
 * @param duration Delay to wait.
 */
Task<void> sleep(std::chrono::steady_clock::duration duration);

}  // namespace ronfire::runtime
