// Lazy, move-only coroutine task.
//
// A Task is suspended on creation and only starts when awaited, spawned, or
// resumed by the event loop. Tasks compose with co_await (a Task is itself an
// awaitable), and an exception thrown inside any task is rethrown at the
// awaiting co_await site or by block_on for the main task.
//
// Ownership: a Task owns its coroutine frame until destroy() (or the
// destructor) runs. Detached tasks are owned by the event loop; the main task
// passed to block_on stays owned by the caller stack, which extracts its
// result before the frame is destroyed.

#pragma once

#include <coroutine>
#include <exception>
#include <functional>
#include <optional>
#include <stdexcept>
#include <utility>

namespace ronfire::runtime {

template <typename T>
struct Task {
  struct promise_type {
    std::coroutine_handle<> parent{};
    bool done = false;
    std::optional<T> value{};
    std::exception_ptr exception{};
    std::function<void()> on_done{};

    Task get_return_object();
    std::suspend_always initial_suspend() noexcept { return {}; }

    struct FinalAwaitable {
      bool await_ready() const noexcept { return false; }
      void await_suspend(std::coroutine_handle<promise_type> h) const noexcept {
        h.promise().done = true;
        if (h.promise().on_done) {
          h.promise().on_done();
        }
        if (auto parent = h.promise().parent) {
          parent.resume();
        }
      }
      void await_resume() const noexcept {}
    };

    FinalAwaitable final_suspend() noexcept { return {}; }
    void return_value(T v) { value = std::move(v); }
    void unhandled_exception() noexcept {
      exception = std::current_exception();
    }
  };

  using handle_type = std::coroutine_handle<promise_type>;

  Task() = default;
  explicit Task(handle_type h) noexcept : handle_(h) {}
  Task(Task&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
  Task(const Task&) = delete;
  Task& operator=(const Task&) = delete;
  Task& operator=(Task&& other) noexcept {
    if (this != &other) {
      destroy();
      handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
  }
  ~Task() { destroy(); }

  handle_type handle() const noexcept { return handle_; }
  bool done() const noexcept { return handle_ != nullptr && handle_.promise().done; }
  void set_on_done(std::function<void()> cb) { handle_.promise().on_done = std::move(cb); }

  // Returns the produced value, rethrowing any exception captured from the
  // coroutine body. The caller must ensure the task has completed.
  T result() {
    if (!done()) {
      throw std::logic_error("Task::result called on incomplete task");
    }
    if (handle_.promise().exception) {
      std::rethrow_exception(handle_.promise().exception);
    }
    return std::move(handle_.promise().value).value();
  }

  void destroy() noexcept {
    if (handle_ != nullptr) {
      handle_.destroy();
      handle_ = nullptr;
    }
  }

  struct Awaiter {
    Task* task;
    bool await_ready() const noexcept { return false; }
    template <typename P>
    void await_suspend(std::coroutine_handle<P> parent) const noexcept {
      task->handle_.promise().parent =
          std::coroutine_handle<>::from_address(parent.address());
      task->handle_.resume();
    }
    T await_resume() {
      if (task->handle_.promise().exception) {
        std::rethrow_exception(task->handle_.promise().exception);
      }
      return std::move(task->handle_.promise().value).value();
    }
  };

  Awaiter operator co_await() & noexcept { return Awaiter{this}; }
  Awaiter operator co_await() && noexcept { return Awaiter{this}; }

 private:
  handle_type handle_ = nullptr;
};

template <typename T>
Task<T> Task<T>::promise_type::get_return_object() {
  return Task{handle_type::from_promise(*this)};
}

template <>
struct Task<void> {
  struct promise_type {
    std::coroutine_handle<> parent{};
    bool done = false;
    std::exception_ptr exception{};
    std::function<void()> on_done{};

    Task get_return_object();
    std::suspend_always initial_suspend() noexcept { return {}; }

    struct FinalAwaitable {
      bool await_ready() const noexcept { return false; }
      void await_suspend(std::coroutine_handle<promise_type> h) const noexcept {
        h.promise().done = true;
        if (h.promise().on_done) {
          h.promise().on_done();
        }
        if (auto parent = h.promise().parent) {
          parent.resume();
        }
      }
      void await_resume() const noexcept {}
    };

    FinalAwaitable final_suspend() noexcept { return {}; }
    void return_void() noexcept {}
    void unhandled_exception() noexcept {
      exception = std::current_exception();
    }
  };

  using handle_type = std::coroutine_handle<promise_type>;

  Task() = default;
  explicit Task(handle_type h) noexcept : handle_(h) {}
  Task(Task&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
  Task(const Task&) = delete;
  Task& operator=(const Task&) = delete;
  Task& operator=(Task&& other) noexcept {
    if (this != &other) {
      destroy();
      handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
  }
  ~Task() { destroy(); }

  handle_type handle() const noexcept { return handle_; }
  bool done() const noexcept { return handle_ != nullptr && handle_.promise().done; }
  void set_on_done(std::function<void()> cb) { handle_.promise().on_done = std::move(cb); }

  // Rethrows any exception captured from the coroutine body. The caller must
  // ensure the task has completed.
  void result() {
    if (!done()) {
      throw std::logic_error("Task::result called on incomplete task");
    }
    if (handle_.promise().exception) {
      std::rethrow_exception(handle_.promise().exception);
    }
  }

  void destroy() noexcept {
    if (handle_ != nullptr) {
      handle_.destroy();
      handle_ = nullptr;
    }
  }

  struct Awaiter {
    Task* task;
    bool await_ready() const noexcept { return false; }
    template <typename P>
    void await_suspend(std::coroutine_handle<P> parent) const noexcept {
      task->handle_.promise().parent =
          std::coroutine_handle<>::from_address(parent.address());
      task->handle_.resume();
    }
    void await_resume() {
      if (task->handle_.promise().exception) {
        std::rethrow_exception(task->handle_.promise().exception);
      }
    }
  };

  Awaiter operator co_await() & noexcept { return Awaiter{this}; }
  Awaiter operator co_await() && noexcept { return Awaiter{this}; }

 private:
  handle_type handle_ = nullptr;
};

inline Task<void> Task<void>::promise_type::get_return_object() {
  return Task{handle_type::from_promise(*this)};
}

}  // namespace ronfire::runtime
