/**
 * @file loop.h
 * @brief Single-threaded event loop built on poll(2).
 *
 * The loop drives every coroutine in the process: readiness waiters settle
 * when a fd becomes ready, deadline waiters settle when a steady-clock
 * deadline passes, and detached tasks spawned via spawn() are owned and
 * reaped here. Because everything runs on one thread, no locks are needed and
 * resumption never races.
 *
 * Current-loop access: block_on() installs its loop as the thread-local
 * current loop before starting the main task; IO awaitables register with
 * current(). A process runs one loop at a time.
 */

#pragma once

#include <chrono>
#include <coroutine>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

#include "runtime/task.h"

namespace ronfire::runtime {

/**
 * @brief Steady-clock time point used for all deadlines.
 */
using Clock = std::chrono::steady_clock;

/**
 * @brief Steady-clock time point used for all deadlines.
 */
using TimePoint = Clock::time_point;

/**
 * @brief Shared mutable state for one waiter.
 *
 * The awaitable and the loop hold the same state so the loop can report a
 * deadline expiry to the coroutine after resuming it.
 */
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

  /**
   * @brief Takes ownership of a coroutine and starts it immediately.
   *
   * The task runs until its first suspension and its frame is destroyed once
   * it completes. Exceptions escaping a detached task are reported to stderr
   * at reaping time.
   *
   * @param task The coroutine to run (moved in).
   */
  void spawn(Task<void> task);

  /**
   * @brief Registers a readiness/deadline waiter for a suspended coroutine.
   *
   * @param fd File descriptor to watch, or -1 for timer-only waits.
   * @param events poll() events (POLLIN/POLLOUT), or 0 for timer-only waits.
   * @param handle The suspended coroutine to resume.
   * @param deadline Absolute deadline, or std::nullopt for no deadline.
   * @param state Shared state the loop marks on deadline expiry.
   */
  void add_waiter(int fd, short events, std::coroutine_handle<> handle,
                  std::optional<TimePoint> deadline,
                  std::shared_ptr<WaiterState> state);

  /**
   * @brief Runs until *done becomes true.
   *
   * The caller keeps the flag alive across the call (block_on owns it on the
   * stack). May throw std::runtime_error on deadlock and std::system_error
   * when poll(2) fails.
   *
   * @param done Pointer to the caller-owned completion flag.
   */
  void run_until(bool* done);

  /**
   * @brief Returns the thread-local current loop, or nullptr outside block_on.
   * @return The current loop.
   */
  static EventLoop* current() noexcept;

  /**
   * @brief Installs (or clears) the thread-local current loop.
   * @param loop The loop to install, or nullptr to clear.
   */
  static void set_current(EventLoop* loop) noexcept;

 private:
  struct Waiter {
    int fd = -1;
    short events = 0;
    std::coroutine_handle<> handle{};
    std::optional<TimePoint> deadline{};
    std::shared_ptr<WaiterState> state;
  };

  /** @brief Destroys frames of detached tasks that have completed. */
  void sweep_finished();

  std::vector<Waiter> waiters_;
  std::vector<std::unique_ptr<Task<void>>> detached_;
  std::vector<std::coroutine_handle<>> finished_;
};

/**
 * @brief Starts the loop, runs main until it completes, returns its result.
 *
 * Rethrows any exception the main task let escape.
 *
 * @tparam T The main task's value type.
 * @param task The main coroutine (moved in).
 * @return The task's value.
 */
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
