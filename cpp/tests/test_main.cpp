// Minimal test harness: no external test framework (dependency-free build).
// Each CHECK records a failure with source location; main exits non-zero if any
// check failed so ctest reports the suite.

#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <iostream>
#include <string>
#include <utility>

#include "cli.h"
#include "runtime/io.h"
#include "runtime/loop.h"
#include "runtime/task.h"

namespace {

using namespace ronfire::runtime;
using ronfire::parse_args;

int g_checks = 0;
int g_failures = 0;

void Report(bool ok, const char* expr, const char* file, int line) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::cerr << file << ':' << line << ": CHECK(" << expr << ") failed\n";
  }
}

}  // namespace

#define CHECK(cond) Report(static_cast<bool>(cond), #cond, __FILE__, __LINE__)

namespace {

// --- runtime: Task values, nesting, and exceptions ---------------------------

Task<int> AddOne(int x) { co_return x + 1; }

Task<int> DoubleAddOne(int x) { co_return co_await AddOne(x) * 2; }

Task<int> Throwing() {
  throw std::runtime_error("boom");
  co_return 0;
}

void TestTaskValues() {
  CHECK(block_on(AddOne(41)) == 42);
  CHECK(block_on(DoubleAddOne(41)) == 84);
}

void TestTaskExceptions() {
  bool caught = false;
  try {
    block_on(Throwing());
  } catch (const std::runtime_error&) {
    caught = true;
  }
  CHECK(caught);
}

// --- runtime: spawn, sleep, and fd IO over socketpair ------------------------

std::pair<int, int> MakeSocketpair() {
  int fds[2] = {-1, -1};
  CHECK(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  set_nonblocking(fds[0]);
  set_nonblocking(fds[1]);
  return {fds[0], fds[1]};
}

void ClosePair(std::pair<int, int> p) {
  ::close(p.first);
  ::close(p.second);
}

// Main-after-spawn: the spawned writer must make progress while main awaits.
Task<void> SpawnWriter(int peer) {
  const char msg[] = "hello";
  co_await write_all(peer, msg, 5, std::nullopt);
  co_return;
}

Task<std::string> EchoThroughPair() {
  auto ends = MakeSocketpair();
  const int mine = ends.first;
  const int peer = ends.second;

  EventLoop* loop = EventLoop::current();
  CHECK(loop != nullptr);
  loop->spawn(SpawnWriter(peer));

  char buffer[16] = {};
  auto got = co_await read_once(mine, buffer, sizeof(buffer), std::nullopt);
  CHECK(got.has_value());
  if (got.has_value()) {
    CHECK(got.value() == 5);
  }
  ClosePair(ends);
  co_return std::string(buffer, 5);
}

void TestSpawnAndFdIo() {
  CHECK(block_on(EchoThroughPair()) == "hello");
}

Task<bool> ReadWithDeadline(int fd, TimePoint deadline) {
  char buffer[8];
  auto got = co_await read_once(fd, buffer, sizeof(buffer), deadline);
  co_return !got.has_value() && got.error().timed_out;
}

void TestReadTimeout() {
  auto ends = MakeSocketpair();
  const auto start = Clock::now();
  const bool timed_out =
      block_on(ReadWithDeadline(ends.first, start + std::chrono::milliseconds(50)));
  const auto elapsed = Clock::now() - start;
  CHECK(timed_out);
  CHECK(elapsed >= std::chrono::milliseconds(50));
  CHECK(elapsed < std::chrono::seconds(5));
  ClosePair(ends);
}

Task<void> WriteThenReadAll(int mine, std::string payload) {
  // Writer runs until all bytes are consumed; the reader below drains them,
  // so this exercises EAGAIN handling on both sides with a payload larger
  // than a default socket buffer.
  const char* data = payload.data();
  co_await write_all(mine, data, payload.size(), std::nullopt);
  co_return;
}

Task<int> DrainAll(int peer, std::size_t expected) {
  std::size_t seen = 0;
  char buffer[4096];
  while (seen < expected) {
    auto got = co_await read_once(peer, buffer, sizeof(buffer), std::nullopt);
    CHECK(got.has_value());
    if (!got.has_value()) {
      break;
    }
    seen += static_cast<std::size_t>(got.value());
  }
  co_return static_cast<int>(seen);
}

Task<int> Transfer(int mine, int peer, std::string payload) {
  EventLoop* loop = EventLoop::current();
  CHECK(loop != nullptr);
  loop->spawn(WriteThenReadAll(mine, payload));
  co_return co_await DrainAll(peer, payload.size());
}

void TestLargeTransfer() {
  auto ends = MakeSocketpair();
  const std::string payload(100'000, 'x');
  // Spawned writer blocks until the main task drains; both must interleave.
  CHECK(block_on(Transfer(ends.first, ends.second, payload)) ==
        static_cast<int>(payload.size()));
  ClosePair(ends);
}

Task<std::chrono::steady_clock::duration> SleepFor(std::chrono::steady_clock::duration d) {
  const auto start = Clock::now();
  co_await sleep(d);
  co_return Clock::now() - start;
}

void TestSleep() {
  const auto elapsed = block_on(SleepFor(std::chrono::milliseconds(30)));
  CHECK(elapsed >= std::chrono::milliseconds(30));
  CHECK(elapsed < std::chrono::seconds(5));
}

// --- cli: parity with the Rust parser --------------------------------------

void TestCliParity() {
  const auto full = parse_args(
      {"ronfire", "/tmp/test.sock", "--config", "/etc/ronfire.conf", "--root", "/srv/site"});
  CHECK(full.has_value());
  if (full.has_value()) {
    CHECK(full.value().socket_path == "/tmp/test.sock");
    CHECK(full.value().config_path == "/etc/ronfire.conf");
    CHECK(full.value().config_explicit);
    CHECK(full.value().root_path == "/srv/site");
  }
  const auto defaults = parse_args({"ronfire"});
  CHECK(defaults.has_value());
  if (defaults.has_value()) {
    CHECK(defaults.value().socket_path == "/tmp/ronfire.sock");
    CHECK(defaults.value().config_path == "ronfire.conf");
    CHECK(!defaults.value().config_explicit);
    CHECK(defaults.value().root_path == ".");
  }
  const auto equals = parse_args({"ronfire", "--config=/x.conf", "--root=/srv"});
  CHECK(equals.has_value() && equals.value().config_path == "/x.conf" &&
        equals.value().root_path == "/srv");
}

void TestCliErrors() {
  CHECK(!parse_args({"ronfire", "--config"}).has_value());
  CHECK(!parse_args({"ronfire", "--config="}).has_value());
  CHECK(!parse_args({"ronfire", "--root"}).has_value());
  CHECK(!parse_args({"ronfire", "--root="}).has_value());
  CHECK(!parse_args({"ronfire", "--bogus"}).has_value());
  CHECK(!parse_args({"ronfire", "-"}).has_value());
  CHECK(!parse_args({"ronfire", "/a.sock", "/b.sock"}).has_value());
  const auto unknown = parse_args({"ronfire", "--bogus"});
  CHECK(!unknown.has_value() && unknown.error() == "unknown option: --bogus");
}

}  // namespace

int main() {
  CHECK(1 + 1 == 2);
  TestTaskValues();
  TestTaskExceptions();
  TestSpawnAndFdIo();
  TestReadTimeout();
  TestLargeTransfer();
  TestSleep();
  TestCliParity();
  TestCliErrors();

  if (g_failures != 0) {
    std::cerr << g_failures << " of " << g_checks << " checks failed\n";
    return 1;
  }
  std::cout << "all " << g_checks << " checks passed\n";
  return 0;
}
