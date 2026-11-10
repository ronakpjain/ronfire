/** @file test_http.cpp @brief HTTP tests. */

#include "test_util.h"

using namespace testutil;

TEST(Http, StrictParsing) {
  const auto ok =
      parse_http_request("GET /a/b?x=1 HTTP/1.1\r\nHost: example\r\n\r\n");
  ASSERT_TRUE(ok.has_value());
  EXPECT_EQ(ok.value().path, "/a/b");
  EXPECT_EQ(ok.value().header("host"),
            std::optional<std::string>("example"));
  // Lowercasing must not confuse same-length header names: a 17-char
  // X-Forwarded-Proto must not match Transfer-Encoding.
  const auto forwarded = parse_http_request(
      "GET / HTTP/1.1\r\nX-Forwarded-Proto: http\r\nAccept-Encoding: gzip\r\n\r\n");
  ASSERT_TRUE(forwarded.has_value());
  EXPECT_FALSE(forwarded.value().header("transfer-encoding").has_value());
  EXPECT_EQ(forwarded.value().header("x-forwarded-proto"),
            std::optional<std::string>("http"));
  ExpectRejected("GET /../secret HTTP/1.1\r\n\r\n");  // traversal
  ExpectRejected("GET /x HTTP/2\r\n\r\n");            // unknown version
  ExpectRejected("GET /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
  ExpectRejected("GET /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
  ExpectRejected("GET /x HTTP/1.1\r\nNoColon\r\n\r\n");
  ExpectRejected("GET /x HTTP/1.1");  // missing CRLFCRLF
}

TEST(Http, KeepAlive) {
  const auto both = parse_http_request(
      "GET / HTTP/1.1\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n");
  ASSERT_TRUE(both.has_value());
  EXPECT_FALSE(both.value().keep_alive());
  const auto v11 = parse_http_request("GET / HTTP/1.1\r\n\r\n");
  ASSERT_TRUE(v11.has_value());
  EXPECT_TRUE(v11.value().keep_alive());
  const auto v10 = parse_http_request("GET / HTTP/1.0\r\n\r\n");
  ASSERT_TRUE(v10.has_value());
  EXPECT_FALSE(v10.value().keep_alive());
}

TEST(Http, RangesAndHead) {
  ronfire::HttpResponse base;
  base.status = "HTTP/1.1 200 OK\r\n";
  base.headers = "Content-Length: 6\r\nContent-Type: application/pdf\r\n\r\n";
  base.body = {'a', 'b', 'c', 'd', 'e', 'f'};

  const auto ranged = finalize_response(
      base, parse_http_request("GET /f HTTP/1.1\r\nRange: bytes=1-3\r\n\r\n")
                .value());
  EXPECT_EQ(ranged.status, "HTTP/1.1 206 Partial Content\r\n");
  EXPECT_EQ(ranged.body, (std::vector<std::uint8_t>{'b', 'c', 'd'}));
  EXPECT_NE(ranged.headers.find("\r\nContent-Range: bytes 1-3/6"),
            std::string::npos);

  const auto head = finalize_response(
      base, parse_http_request("HEAD /f HTTP/1.1\r\nRange: bytes=1-3\r\n\r\n")
                .value());
  EXPECT_TRUE(head.body.empty());
  EXPECT_NE(head.headers.find("\r\nContent-Length: 3"), std::string::npos);

  const auto unsat = finalize_response(
      base, parse_http_request("GET /f HTTP/1.1\r\nRange: bytes=99-100\r\n\r\n")
                .value());
  EXPECT_EQ(unsat.status.rfind("HTTP/1.1 416", 0), 0);
  EXPECT_NE(unsat.headers.find("\r\nContent-Range: bytes */6"),
            std::string::npos);
  const auto suffix = finalize_response(
      base, parse_http_request("GET /f HTTP/1.1\r\nRange: bytes=-3\r\n\r\n")
                .value());
  EXPECT_EQ(suffix.status, "HTTP/1.1 206 Partial Content\r\n");
  EXPECT_EQ((suffix.body == std::vector<std::uint8_t>{'d', 'e', 'f'}), true);
  const auto open = finalize_response(
      base, parse_http_request("GET /f HTTP/1.1\r\nRange: bytes=4-\r\n\r\n")
                .value());
  EXPECT_EQ((open.body == std::vector<std::uint8_t>{'e', 'f'}), true);
  EXPECT_FALSE(parse_range_header("bytes=0-1,2-3").has_value());
  const auto ctrl = parse_http_request(std::string("GET / HTTP/1.1\r\nX: a") +
                                       '\x01' + "b\r\n\r\n");
  EXPECT_FALSE(ctrl.has_value());
  std::string not_utf8 = "GET / HTTP/1.1\r\n";
  not_utf8 += '\xff';
  not_utf8 += "\r\n\r\n";
  EXPECT_FALSE(parse_http_request(not_utf8).has_value());
}

TEST(Http, Framing) {
  SocketPair pair;
  // Split writes + pipelining: two requests must parse in order.
  auto scenario = [&]() -> Task<bool> {
    const std::string wire =
        "GET /one HTTP/1.1\r\nHost: ex"
        "ample\r\n\r\nGET /two HTTP/1.1\r\n\r\n";
    auto written = co_await write_all(pair.second(), wire.data(), wire.size(),
                                      std::nullopt);
    if (!written.has_value()) co_return false;
    ronfire::BufferedReader reader(pair.first());
    auto first = co_await reader.read_next(std::nullopt);
    if (!(first.has_value() && first.value().has_value() &&
          first.value()->path == "/one")) {
      co_return false;
    }
    auto second = co_await reader.read_next(std::nullopt);
    co_return second.has_value() && second.value().has_value() &&
              second.value()->path == "/two";
  };
  EXPECT_TRUE(block_on(scenario()));

  // Header cap: oversized block without a terminator.
  SocketPair capped;
  auto capped_scenario = [&]() -> Task<bool> {
    const std::string payload(ronfire::kMaxRequestHeaderBytes, 'a');
    EventLoop::current()->spawn(BigWriter(capped.second(), payload));
    ronfire::BufferedReader reader(capped.first());
    auto got = co_await reader.read_next(std::nullopt);
    co_return !got.has_value() &&
              got.error().kind ==
                  ronfire::RequestReadError::Kind::HeaderTooLarge;
  };
  EXPECT_TRUE(block_on(capped_scenario()));

  // Idle deadline.
  SocketPair idle;
  auto idle_scenario = [&]() -> Task<bool> {
    ronfire::BufferedReader reader(idle.first());
    auto got = co_await reader.read_next(
        Clock::now() + std::chrono::milliseconds(50));
    co_return !got.has_value() &&
              got.error().kind == ronfire::RequestReadError::Kind::TimedOut;
  };
  EXPECT_TRUE(block_on(idle_scenario()));

  // Clean EOF vs partial EOF.
  SocketPair eof;
  ::shutdown(eof.second(), SHUT_WR);
  EXPECT_TRUE(block_on([&]() -> Task<bool> {
    ronfire::BufferedReader reader(eof.first());
    auto got = co_await reader.read_next(std::nullopt);
    co_return got.has_value() && !got.value().has_value();
  }()));
  SocketPair partial;
  auto partial_scenario = [&]() -> Task<bool> {
    const std::string wire = "GET /one HTTP/1.1\r\n";
    auto written = co_await write_all(partial.second(), wire.data(), wire.size(),
                                      std::nullopt);
    if (!written.has_value()) co_return false;
    ::shutdown(partial.second(), SHUT_WR);
    ronfire::BufferedReader reader(partial.first());
    auto got = co_await reader.read_next(std::nullopt);
    co_return !got.has_value() &&
              got.error().kind == ronfire::RequestReadError::Kind::Malformed;
  };
  EXPECT_TRUE(block_on(partial_scenario()));
}

