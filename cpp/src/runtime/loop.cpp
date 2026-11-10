/** @file loop.cpp @brief Implementation. */

// Poll-based event loop implementation. See loop.h for the design.

#include "runtime/loop.h"

#include <poll.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

namespace ronfire::runtime {
namespace {

thread_local EventLoop* g_current = nullptr;

}  // namespace

EventLoop* EventLoop::current() noexcept { return g_current; }

void EventLoop::set_current(EventLoop* loop) noexcept { g_current = loop; }

void EventLoop::spawn(Task<void> task) {
  const auto handle = task.handle();
  task.set_on_done([this, handle] { finished_.push_back(handle); });
  detached_.push_back(std::make_unique<Task<void>>(std::move(task)));
  detached_.back()->handle().resume();
}

void EventLoop::add_waiter(int fd, short events, std::coroutine_handle<> handle,
                           std::optional<TimePoint> deadline,
                           std::shared_ptr<WaiterState> state) {
  Waiter waiter;
  waiter.fd = fd;
  waiter.events = events;
  waiter.handle = handle;
  waiter.deadline = deadline;
  waiter.state = std::move(state);
  waiters_.push_back(std::move(waiter));
}

void EventLoop::sweep_finished() {
  if (finished_.empty()) {
    return;
  }
  for (auto finished : finished_) {
    for (auto it = detached_.begin(); it != detached_.end(); ++it) {
      if ((*it)->handle().address() == finished.address()) {
        if ((*it)->handle().promise().exception) {
          std::fprintf(stderr, "unhandled exception in detached task\n");
        }
        detached_.erase(it);
        break;
      }
    }
  }
  finished_.clear();
}

void EventLoop::run_until(bool* done) {
  while (!*done) {
    sweep_finished();

    std::vector<struct pollfd> fds;
    for (const auto& waiter : waiters_) {
      if (waiter.fd >= 0) {
        fds.push_back(pollfd{waiter.fd, waiter.events, 0});
      }
    }

    int timeout_ms = -1;
    auto now = Clock::now();
    for (const auto& waiter : waiters_) {
      if (waiter.deadline.has_value()) {
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(*waiter.deadline - now)
                .count();
        const int clamped = ms < 0 ? 0 : static_cast<int>(ms);
        if (timeout_ms < 0 || clamped < timeout_ms) {
          timeout_ms = clamped;
        }
      }
    }

    if (waiters_.empty()) {
      throw std::runtime_error("event loop deadlock: no waiters and main task incomplete");
    }

    const int ready = ::poll(fds.data(), static_cast<nfds_t>(fds.size()), timeout_ms);
    if (ready < 0 && errno != EINTR) {
      throw std::system_error(errno, std::generic_category(), "poll");
    }
    now = Clock::now();

    // Collect settled waiters first, then resume them: resuming runs arbitrary
    // coroutine code that may register new waiters on the same fds.
    std::vector<Waiter> settled;
    std::vector<Waiter> pending;
    pending.reserve(waiters_.size());
    for (auto& waiter : waiters_) {
      bool settle = false;
      if (ready > 0 && waiter.fd >= 0) {
        for (const auto& pfd : fds) {
          if (pfd.fd == waiter.fd && (pfd.revents & (waiter.events | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            settle = true;
            break;
          }
        }
      }
      if (!settle && waiter.deadline.has_value() && *waiter.deadline <= now) {
        waiter.state->timed_out = true;
        settle = true;
      }
      if (settle) {
        settled.push_back(std::move(waiter));
      } else {
        pending.push_back(std::move(waiter));
      }
    }
    waiters_.swap(pending);

    for (auto& waiter : settled) {
      waiter.handle.resume();
    }
    sweep_finished();
  }
  sweep_finished();
}

}  // namespace ronfire::runtime
