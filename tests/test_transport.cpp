/** @file test_transport.cpp @brief Transport tests. */

#include "test_util.h"

using namespace testutil;

TEST(Transport, BindSendReceive) {
  namespace transport = ronfire;
  const std::string path =
      "/tmp/ronfire-transport-test-" + std::to_string(::getpid()) + ".sock";
  auto listener = transport::create_socket(path);
  ASSERT_TRUE(listener.has_value()) << "bind failed";
  // Blocking client connecting to the bound path.
  const int client = ::socket(AF_UNIX, SOCK_STREAM, 0);
  ASSERT_GE(client, 0);
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  path.copy(address.sun_path, path.size());
  address.sun_path[path.size()] = '\0';
  ASSERT_EQ(::connect(client,
                      reinterpret_cast<const sockaddr*>(&address),
                      sizeof(address)), 0);
  // Accept + send via the runtime; client reads back synchronously.
  auto scenario = [&]() -> Task<bool> {
    auto accepted = co_await transport::accept_once(listener.value(),
                                                    std::nullopt);
    if (!accepted.has_value()) co_return false;
    ronfire::HttpResponse response;
    response.status = "HTTP/1.1 200 OK\r\n";
    response.headers = "Content-Length: 2\r\n\r\n";
    response.body = {'h', 'i'};
    auto sent = co_await transport::send_response(
        accepted.value(), response, nullptr);
    ::close(accepted.value());
    co_return sent.has_value();
  };
  EXPECT_TRUE(block_on(scenario()));
  char buffer[128];
  const ssize_t n = ::read(client, buffer, sizeof(buffer));
  EXPECT_GT(n, 0);
  EXPECT_NE(std::string(buffer, static_cast<std::size_t>(n))
                .find("HTTP/1.1 200 OK"),
            std::string::npos);
  ::close(client);
  ::close(listener.value());
  ::unlink(path.c_str());
}

