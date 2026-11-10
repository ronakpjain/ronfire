/** @file test_runtime.cpp @brief Runtime tests. */

#include "test_util.h"

using namespace testutil;

TEST(Runtime, TaskValuesAndNesting) {
  EXPECT_EQ(block_on([]() -> Task<int> { co_return 42; }()), 42);
  EXPECT_EQ(block_on([]() -> Task<int> {
    auto inner = []() -> Task<int> { co_return 21; }();
    co_return co_await inner * 2;
  }()), 42);
}

TEST(Runtime, TaskExceptionsPropagate) {
  EXPECT_THROW(block_on([]() -> Task<int> {
    throw std::runtime_error("boom");
    co_return 0;
  }()), std::runtime_error);
}

TEST(Runtime, SpawnInterleaving) {
  SocketPair pair;
  auto scenario = [&]() -> Task<std::string> {
    EventLoop::current()->spawn(Writer("hello", pair.second()));
    std::string out;
    char buffer[16];
    while (out.size() < 5) {
      auto got =
          co_await read_once(pair.first(), buffer, sizeof(buffer), std::nullopt);
      EXPECT_TRUE(got.has_value());
      if (!got.has_value()) break;
      out.append(buffer, static_cast<std::size_t>(got.value()));
    }
    co_return out;
  };
  EXPECT_EQ(block_on(scenario()), "hello");
}

TEST(Runtime, BackpressureLargeTransfer) {
  SocketPair pair;
  const std::string payload(100'000, 'x');
  auto scenario = [&]() -> Task<std::size_t> {
    EventLoop::current()->spawn(BigWriter(pair.second(), payload));
    co_return co_await Drain(pair.first(), payload.size());
  };
  EXPECT_EQ(block_on(scenario()), payload.size());
}

TEST(Runtime, DeadlineAndSleep) {
  SocketPair pair;
  const auto start = Clock::now();
  const bool timed_out = block_on([&]() -> Task<bool> {
    char buffer[8];
    auto got = co_await read_once(pair.first(), buffer, sizeof(buffer),
                                  start + std::chrono::milliseconds(50));
    co_return !got.has_value() && got.error().timed_out;
  }());
  EXPECT_TRUE(timed_out);
  EXPECT_GE(Clock::now() - start, std::chrono::milliseconds(50));
  EXPECT_LT(Clock::now() - start, std::chrono::seconds(5));
  EXPECT_NO_THROW(block_on(sleep(std::chrono::milliseconds(10))));
}

