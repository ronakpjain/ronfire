/** @file loop.h @brief Single-threaded poll(2) event loop. */

#pragma once

#include <poll.h>

#include <chrono>
#include <coroutine>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

#include "runtime/task.h"

namespace ronfire::runtime {

/** @brief Steady clock / time point for deadlines. */
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

/** @brief Shared waiter state (deadline flag) between loop and awaitable. */
struct WaiterState {
  bool timed_out = false;
};

/**
 * @brief Single-threaded poll event loop owning detached tasks and waiters.
 */
class EventLoop {
 public:
  EventLoop() = default;
  EventLoop(const EventLoop&) = delete;
  EventLoop& operator=(const EventLoop&) = delete;

  /** @brief Runs a coroutine to completion, owning its frame. */
  /** @param task Coroutine to run. */

  void spawn(Task<void> task);

  /** @brief Registers a waiter for a suspended coroutine. */
  void add_waiter(int fd, short events, std::coroutine_handle<> handle,
                  std::optional<TimePoint> deadline,
                  std::shared_ptr<WaiterState> state);

  /** @brief Runs until *done is true. @param done Caller-owned flag. */
  void run_until(bool* done);

  /** @brief Returns the thread-local current loop, or nullptr. */
  static EventLoop* current() noexcept;

  /** @brief Installs or clears the current loop. */
  static void set_current(EventLoop* loop) noexcept;

 private:
  struct Waiter {
    int fd = -1;
    short events = 0;
    std::coroutine_handle<> handle{};
    std::optional<TimePoint> deadline{};
    std::shared_ptr<WaiterState> state;
  };

  /** @brief Destroys finished detached frames. */
  void sweep_finished();

  std::vector<Waiter> waiters_;
  std::vector<std::unique_ptr<Task<void>>> detached_;
  std::vector<std::coroutine_handle<>> finished_;
  // Reused loop buffers (pollfd set + settled/pending waiters); cleared
  // every iteration so no per-cycle heap allocation happens.
  std::vector<struct pollfd> pollfds_;
  std::vector<Waiter> settled_;
  std::vector<Waiter> pending_;
};

/** @brief Runs the main task to completion, returning its value. */
template <typename T>
T block_on(Task<T> task) {
  EventLoop loop;
  EventLoop::set_current(&loop);
  struct CurrentGuard {
    ~CurrentGuard() { EventLoop::set_current(nullptr); }
  } guard;
  bool main_done = false;
  task.set_on_done([&main_done] { main_done = true; });
  task.handle().resume();
  if (!task.done()) {
    loop.run_until(&main_done);
  }
  if constexpr (std::is_void_v<T>) {
    task.result();
    return;
  } else {
    return task.result();
  }
}

}  // namespace ronfire::runtime
