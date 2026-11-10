/** @file test_proxy.cpp @brief Proxy plugin tests. */

#include "test_util.h"

#include <arpa/inet.h>
#include <atomic>
#include <netinet/in.h>

using namespace testutil;

namespace {

/** @brief Loopback TCP upstream serving canned responses in order. */
struct UpstreamServer {
  int listener = -1;
  int port = 0;
  std::atomic<int> accepted{0};
  UpstreamServer() {
    listener = ::socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(listener, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(0x7F000001u);  // 127.0.0.1
    address.sin_port = 0;
    EXPECT_TRUE(::bind(listener, reinterpret_cast<const sockaddr*>(&address),
                       sizeof(address)) == 0);
    EXPECT_TRUE(::listen(listener, 16) == 0);
    socklen_t len = sizeof(address);
    EXPECT_TRUE(
        ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &len) ==
        0);
    port = ntohs(address.sin_port);
    set_nonblocking(listener);
  }
  ~UpstreamServer() {
    if (listener >= 0) ::close(listener);
  }
  UpstreamServer(const UpstreamServer&) = delete;
  UpstreamServer& operator=(const UpstreamServer&) = delete;
};

Task<void> ServeMany(int listener, std::vector<std::string> responses,
                     std::atomic<int>* accepted,
                     std::atomic<int>* good_paths = nullptr) {
  for (const auto& response : responses) {
    auto connection = co_await ronfire::accept_once(listener, std::nullopt);
    if (!connection.has_value()) {
      co_return;
    }
    accepted->fetch_add(1);
    char buffer[4096];
    std::string discarded;
    auto deadline = Clock::now() + std::chrono::seconds(2);
    while (discarded.find("\r\n\r\n") == std::string::npos) {
      auto got = co_await read_once(connection.value(), buffer, sizeof(buffer),
                                   deadline);
      if (!got.has_value() || got.value() == 0) {
        break;
      }
      discarded.append(buffer, static_cast<std::size_t>(got.value()));
    }
    // Count well-formed targets so a broken fetch (empty path) fails loudly.
    if (good_paths != nullptr && discarded.rfind("GET /", 0) == 0) {
      good_paths->fetch_add(1);
    }
    co_await write_all(connection.value(), response.data(), response.size(),
                       std::nullopt);
    ::close(connection.value());
  }
  co_return;
}

ronfire::RouteConfig LoadProxyConfig(
    const std::string& url, const std::string& cache_seconds = "0") {
  const std::string contents = "[plugin.proxy.one]\n"
                               "route = /api/item\n"
                               "url = " +
                               url +
                               "\n"
                               "content_type = application/json\n"
                               "cache_seconds = " +
                               cache_seconds +
                               "\n"
                               "timeout_seconds = 5\n"
                               "max_bytes = 1048576\n";
  return ronfire::RouteConfig::parse(contents);
}

}  // namespace
TEST(Proxy, FactoryValidation) {
  const std::string valid =
      "[plugin.proxy.one]\n"
      "route = /api/item\n"
      "url = http://127.0.0.1/item\n"
      "content_type = text/plain\n"
      "cache_seconds = 0\n"
      "timeout_seconds = 1\n"
      "max_bytes = 10\n";
  EXPECT_NO_THROW(ronfire::RouteConfig::parse(valid));
  const auto bad = [](const std::string& contents) {
    try {
      ronfire::RouteConfig::parse(contents);
      return false;
    } catch (const ronfire::ConfigError&) {
      return true;
    }
  };
  EXPECT_TRUE(bad("[plugin.proxy.one]\nroute=/a\nurl=http://x/\n"
                  "content_type=text/plain\ncache_seconds=0\n"
                  "timeout_seconds=1\nmax_bytes=10\nunknown=1\n"));
  EXPECT_TRUE(bad("[plugin.proxy.one]\nroute=/a\nurl=ftp://x/\n"
                  "content_type=text/plain\ncache_seconds=0\n"
                  "timeout_seconds=1\nmax_bytes=10\n"));
  EXPECT_TRUE(bad("[plugin.proxy.one]\nroute=/a\nurl=http://user@x/\n"
                  "content_type=text/plain\ncache_seconds=0\n"
                  "timeout_seconds=1\nmax_bytes=10\n"));
  EXPECT_TRUE(bad("[plugin.proxy.one]\nroute=/a\nurl=http://x/\n"
                  "content_type=text/plain\ncache_seconds=0\n"
                  "timeout_seconds=0\nmax_bytes=10\n"));
  EXPECT_TRUE(bad("[plugin.proxy.one]\nroute=relative\nurl=http://x/\n"
                  "content_type=text/plain\ncache_seconds=0\n"
                  "timeout_seconds=1\nmax_bytes=10\n"));
}

TEST(Proxy, LoopbackFetchCacheAndErrors) {
  UpstreamServer server;
  std::atomic<int> good_paths{0};
  const std::string body = "{\"ok\":true}";
  const std::string canned = "HTTP/1.1 200 OK\r\nContent-Length: " +
                             std::to_string(body.size()) +
                             "\r\nContent-Type: application/json\r\n\r\n" + body;
  const std::string url =
      "http://127.0.0.1:" + std::to_string(server.port) + "/item";
  auto scenario = [&]() -> Task<std::pair<std::string, int>> {
    EventLoop::current()->spawn(
        ServeMany(server.listener, {canned}, &server.accepted, &good_paths));
    auto routes = LoadProxyConfig(url, "60");
    ronfire::TtlCache cache;
    auto first = co_await ronfire::dispatch_request(
        routes, parse_http_request("GET /api/item HTTP/1.1\r\n\r\n").value(),
        cache);
    // Upstream is exhausted after one connection; the second hit must come
    // from the cache.
    auto second = co_await ronfire::dispatch_request(
        routes, parse_http_request("GET /api/item HTTP/1.1\r\n\r\n").value(),
        cache);
    const std::string text = std::string(first->body.begin(), first->body.end());
    co_return std::make_pair(text, server.accepted.load());
  };
  const auto result = block_on(scenario());
  EXPECT_EQ(result.first, body);
  EXPECT_EQ(result.second, 1);
  EXPECT_EQ(good_paths.load(), 1);

  // Upstream 404 without cache maps to 502.
  UpstreamServer missing;
  auto missing_scenario = [&]() -> Task<bool> {
    EventLoop::current()->spawn(ServeMany(
        missing.listener,
        {"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"},
        &missing.accepted));
    auto routes = LoadProxyConfig(
        "http://127.0.0.1:" + std::to_string(missing.port) + "/nope", "0");
    ronfire::TtlCache cache;
    auto response = co_await ronfire::dispatch_request(
        routes, parse_http_request("GET /api/item HTTP/1.1\r\n\r\n").value(),
        cache);
    co_return response.has_value() &&
              response->status.rfind("HTTP/1.1 502", 0) == 0;
  };
  EXPECT_TRUE(block_on(missing_scenario()));

}

TEST(Proxy, RedirectFollowsAllowlistedHost) {
  UpstreamServer server;
  std::atomic<int> good_paths{0};
  const std::string final_url =
      "http://127.0.0.1:" + std::to_string(server.port) + "/final";
  const std::string redirect = "HTTP/1.1 302 Found\r\nLocation: " + final_url +
                               "\r\nContent-Length: 0\r\n\r\n";
  const std::string done = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nfinal";
  auto scenario = [&]() -> Task<std::string> {
    EventLoop::current()->spawn(
        ServeMany(server.listener, {redirect, done}, &server.accepted,
                  &good_paths));
    auto routes = LoadProxyConfig(
        "http://127.0.0.1:" + std::to_string(server.port) + "/start", "0");
    ronfire::TtlCache cache;
    auto response = co_await ronfire::dispatch_request(
        routes, parse_http_request("GET /api/item HTTP/1.1\r\n\r\n").value(),
        cache);
    co_return std::string(response->body.begin(), response->body.end());
  };
  EXPECT_EQ(block_on(scenario()), "final");
  EXPECT_EQ(server.accepted.load(), 2);
  EXPECT_EQ(good_paths.load(), 2);
}
