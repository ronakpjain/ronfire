/** @file test_util.h @brief Shared helpers for the test suites. */

#pragma once

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "cli.h"
#include "http.h"
#include "plugins.h"
#include "plugins/proxy.h"
#include "runtime/io.h"
#include "runtime/loop.h"
#include "runtime/task.h"
#include "static_files.h"
#include "transport.h"

namespace testutil {

using namespace ronfire::runtime;
using ronfire::finalize_response;
using ronfire::parse_http_request;
using ronfire::parse_range_header;
using ronfire::parse_args;

/**
 * @brief RAII non-blocking Unix socketpair for tests.
 */
class SocketPair {
 public:
  SocketPair() {
    int fds[2] = {-1, -1};
    EXPECT_TRUE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0)
        << "socketpair failed";
    set_nonblocking(fds[0]);
    set_nonblocking(fds[1]);
    fds_[0] = fds[0];
    fds_[1] = fds[1];
  }
  ~SocketPair() {
    if (fds_[0] >= 0) ::close(fds_[0]);
    if (fds_[1] >= 0) ::close(fds_[1]);
  }
  SocketPair(const SocketPair&) = delete;
  SocketPair& operator=(const SocketPair&) = delete;

  /** @brief First end. */
  int first() const { return fds_[0]; }
  /** @brief Second end. */
  int second() const { return fds_[1]; }

 private:
  int fds_[2];
};

/**
 * @brief Writes a fixed message from the peer end.
 * @param peer Peer fd.
 * @param text Message to write.
 */
inline Task<void> Writer(const char* text, int peer) {
  const std::string payload = text;
  co_await write_all(peer, payload.data(), payload.size(), std::nullopt);
  co_return;
}

/**
 * @brief Drains exactly expected bytes.
 * @param reader_fd Reader fd.
 * @param expected Byte count to drain.
 * @return Byte count drained.
 */
inline Task<std::size_t> Drain(int reader_fd, std::size_t expected) {
  std::size_t seen = 0;
  char buffer[4096];
  while (seen < expected) {
    auto got = co_await read_once(reader_fd, buffer, sizeof(buffer), std::nullopt);
    if (!got.has_value()) break;
    seen += static_cast<std::size_t>(got.value());
  }
  co_return seen;
}

/**
 * @brief Writer half of the large-transfer test.
 * @param writer_fd Writer fd.
 * @param payload Payload to write.
 */
inline Task<void> BigWriter(int writer_fd, std::string payload) {
  co_await write_all(writer_fd, payload.data(), payload.size(), std::nullopt);
  co_return;
}

/**
 * @brief Asserts that a request string is rejected.
 * @param request Raw request bytes.
 */
inline void ExpectRejected(const std::string& request) {
  EXPECT_FALSE(parse_http_request(request).has_value()) << request;
}

}  // namespace testutil
