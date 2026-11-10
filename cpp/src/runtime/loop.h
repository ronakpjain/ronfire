// Single-threaded event loop built on poll(2).
//
// The loop drives every coroutine in the process: readiness waiters settle when
// a fd becomes ready, deadline waiters settle when a steady-clock deadline
// passes (or fail as timed out), and detached tasks spawned via spawn() are
// owned and reaped here. Because everything runs on one thread, no locks are
// needed and resumption never races.
//
// Current-loop access: block_on() installs its loop as the thread-local current
// loop before starting the main task; IO awaitables register themselves with
// current(). A process runs one loop at a time.

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

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// Shared mutable state for one waiter. The awaitable and the loop hold the
// same state so the loop can report a deadline expiry to the coroutine after
// resuming it.
struct WaiterState {
  bool timed_out = false;
};

class EventLoop {
 public:
  EventLoop() = default;
  EventLoop(const EventLoop&) = delete;
  EventLoop& operator=(const EventLoop&) = delete;

  // Takes ownership of a coroutine, starts it immediately (it runs until its
  // first suspension), and destroys its frame once it completes. Exceptions
  // escaping a detached task are reported to stderr at reaping time.
  void spawn(Task<void> task);

  // Registers a waiter, replacing nothing: each awaitable creates a fresh
  // waiter for one suspension. fd may be -1 for timer-only waits, events is
  // 0 when only the deadline matters.
  void add_waiter(int fd, short events, std::coroutine_handle<> handle,
                  std::optional<TimePoint> deadline,
                  std::shared_ptr<WaiterState> state);

  // Runs until *done becomes true. The caller keeps the flag alive across the
  // call (block_on owns it on the stack).
  void run_until(bool* done);

  static EventLoop* current() noexcept;
  static void set_current(EventLoop* loop) noexcept;

 private:
  struct Waiter {
    int fd = -1;
    short events = 0;
    std::coroutine_handle<> handle{};
    std::optional<TimePoint> deadline{};
    std::shared_ptr<WaiterState> state;
  };

  void sweep_finished();

  std::vector<Waiter> waiters_;
  std::vector<std::unique_ptr<Task<void>>> detached_;
  std::vector<std::coroutine_handle<>> finished_;
};

// Starts the loop, runs main until it completes, and returns its result
// (rethrowing any exception the main task let escape).
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
