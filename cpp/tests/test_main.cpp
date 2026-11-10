/**
 * @file test_main.cpp
 * @brief Contract tests for the C++ server (GoogleTest).
 *
 * Only important behaviour is covered: coroutine composition and error
 * propagation, single-threaded fd interleaving under backpressure, deadline
 * handling, CLI parity, strict HTTP rejection, keep-alive, range/HEAD
 * finalization, and request framing (pipelining, caps, timeout, EOF).
 *
 * GoogleTest is a test-only dependency; the server binary links only the
 * C++ standard library and POSIX.
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include "cli.h"
#include "http.h"
#include "plugins.h"
#include "runtime/io.h"
#include "runtime/loop.h"
#include "runtime/task.h"
#include "static_files.h"
#include "transport.h"

namespace {

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
Task<void> Writer(const char* text, int peer) {
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
Task<std::size_t> Drain(int reader_fd, std::size_t expected) {
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
Task<void> BigWriter(int writer_fd, std::string payload) {
  co_await write_all(writer_fd, payload.data(), payload.size(), std::nullopt);
  co_return;
}

/**
 * @brief Asserts that a request string is rejected.
 * @param request Raw request bytes.
 */
void ExpectRejected(const std::string& request) {
  EXPECT_FALSE(parse_http_request(request).has_value()) << request;
}

}  // namespace

// --- plugins -----------------------------------------------------------------

namespace {

class TestFactory : public ronfire::PluginFactory {
 public:
  std::shared_ptr<ronfire::PluginHandler> build(
      const std::string&, const std::map<std::string, std::string>& fields)
      override;
};

class TestHandler : public ronfire::PluginHandler {
 public:
  explicit TestHandler(std::string path) : path_(std::move(path)) {}
  std::string route() const override { return path_; }
  Task<ronfire::HttpResponse> dispatch(const ronfire::PluginRequest&,
                                       ronfire::TtlCache&) override {
    ronfire::HttpResponse response;
    response.status = "HTTP/1.1 200 OK\r\n";
    response.headers = "Content-Length: 2\r\n\r\n";
    response.body = {'o', 'k'};
    co_return response;
  }

 private:
  std::string path_;
};

}  // namespace

std::shared_ptr<ronfire::PluginHandler> TestFactory::build(
    const std::string&, const std::map<std::string, std::string>& fields) {
  const auto it = fields.find("route");
  if (it == fields.end()) {
    throw ronfire::ConfigError("missing route");
  }
  return std::make_shared<TestHandler>(it->second);
}

TEST(Plugins, ParseAndExactDispatch) {
  ronfire::PluginRegistry registry;
  registry.register_plugin("test", std::make_shared<TestFactory>());
  auto routes = ronfire::RouteConfig::parse_with_registry(
      "# comment\n[plugin.test.one]\nroute = /exact\n", registry);
  EXPECT_EQ(routes.route_count(), 1);
  EXPECT_TRUE(routes.route_for("/exact").has_value());
  EXPECT_FALSE(routes.route_for("/exact/x").has_value());
  ronfire::TtlCache cache;
  const auto hit = block_on(ronfire::dispatch_request(
      routes,
      parse_http_request("GET /exact?ignored=1 HTTP/1.1\r\n\r\n").value(),
      cache));
  ASSERT_TRUE(hit.has_value());
  EXPECT_EQ(hit->body.size(), 2u);
  const auto miss = block_on(ronfire::dispatch_request(
      routes, parse_http_request("GET /other HTTP/1.1\r\n\r\n").value(),
      cache));
  EXPECT_FALSE(miss.has_value());
}

TEST(Plugins, Rejections) {
  ronfire::PluginRegistry registry;
  registry.register_plugin("test", std::make_shared<TestFactory>());
  const auto bad = [
    &registry](const std::string& contents) {
        try {
          ronfire::RouteConfig::parse_with_registry(contents, registry);
          return false;
        } catch (const ronfire::ConfigError&) {
          return true;
        }
      };
  EXPECT_TRUE(bad("[plugin.unknown.one]\nroute=/a"));
  EXPECT_TRUE(bad("[plugin.test.one]\nroute=/a\n[plugin.test.one]\nroute=/b"));
  EXPECT_TRUE(bad("[plugin.test.one]\nroute=/a\n[plugin.test.two]\nroute=/a"));
  EXPECT_TRUE(bad("[plugin.test.one]\nroute=/a\nroute=/b"));
  EXPECT_TRUE(bad("route=/a"));
  EXPECT_TRUE(bad("[plugin.test.one]\nnoequals"));
}

TEST(Plugins, TtlCacheFreshAndStale) {
  ronfire::TtlCache cache;
  EXPECT_FALSE(cache.stale("/r").has_value());
  cache.put("/r", {1, 2}, std::chrono::seconds(60));
  EXPECT_TRUE(cache.fresh("/r").has_value());
  cache.put("/r", {3}, std::chrono::seconds(0));
  EXPECT_FALSE(cache.fresh("/r").has_value());
  EXPECT_TRUE(cache.stale("/r").has_value());
}

// --- static files ------------------------------------------------------------

void WriteFile(const std::filesystem::path& path, const std::string& text) {
  std::ofstream out(path);
  out << text;
}

TEST(Static, DocumentRootContainment) {
  namespace fs = std::filesystem;
  const fs::path base = fs::temp_directory_path() /
                        ("ronfire-test-" + std::to_string(::getpid()));
  const fs::path root = base / "root";
  std::error_code ec;
  fs::remove_all(base, ec);
  fs::create_directories(root / "sub");
  fs::create_directories(root / ".git");
  WriteFile(root / "index.html", "<h1>root</h1>");
  WriteFile(root / "page.html", "<h1>page</h1>");
  WriteFile(root / "sub" / "index.html", "<h1>sub</h1>");
  WriteFile(root / "app.log", "secret");
  WriteFile(root / ".git" / "config", "secret");
  WriteFile(root / "denied.txt", "denied");
  WriteFile(base / "outside.txt", "outside");
  fs::create_symlink(base / "outside.txt", root / "link.txt");

  const auto docroot = ronfire::DocumentRoot::make(
      root.string(), (root / "denied.txt").string());
  ASSERT_TRUE(docroot.has_value()) << docroot.error();
  const auto& root_ref = docroot.value();
  EXPECT_TRUE(root_ref.resolve("/").has_value());
  EXPECT_TRUE(root_ref.resolve("/page").has_value());
  EXPECT_TRUE(root_ref.resolve("/sub/").has_value());
  EXPECT_FALSE(root_ref.resolve("/app.log").has_value());
  EXPECT_FALSE(root_ref.resolve("/.git/config").has_value());
  EXPECT_FALSE(root_ref.resolve("/../outside.txt").has_value());
  EXPECT_FALSE(root_ref.resolve("/denied.txt").has_value());
  EXPECT_FALSE(root_ref.resolve("/link.txt").has_value());
  EXPECT_FALSE(root_ref.resolve("/missing.html").has_value());
  const auto page = root_ref.resolve("/page");
  ASSERT_TRUE(page.has_value());
  const auto response = ronfire::generate_response(*page);
  EXPECT_EQ(response.status, "HTTP/1.1 200 OK\r\n");
  EXPECT_NE(response.headers.find("Content-Type: text/html"),
            std::string::npos);
  EXPECT_EQ(ronfire::guess_mime_type("/x/Resume.pdf"), "application/pdf");
  fs::remove_all(base, ec);
}

// --- transport ---------------------------------------------------------------

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

// --- runtime -----------------------------------------------------------------

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

// --- cli ---------------------------------------------------------------------

TEST(Cli, DefaultsAndFlags) {
  const auto defaults = parse_args({"ronfire"});
  ASSERT_TRUE(defaults.has_value());
  EXPECT_EQ(defaults.value().socket_path, "/tmp/ronfire.sock");
  EXPECT_EQ(defaults.value().config_path, "ronfire.conf");
  EXPECT_FALSE(defaults.value().config_explicit);
  EXPECT_EQ(defaults.value().root_path, ".");
  const auto full = parse_args(
      {"ronfire", "/tmp/a.sock", "--config=/x.conf", "--root", "/srv"});
  ASSERT_TRUE(full.has_value());
  EXPECT_EQ(full.value().socket_path, "/tmp/a.sock");
  EXPECT_EQ(full.value().config_path, "/x.conf");
  EXPECT_TRUE(full.value().config_explicit);
  EXPECT_EQ(full.value().root_path, "/srv");
}

TEST(Cli, Errors) {
  const auto unknown = parse_args({"ronfire", "--bogus"});
  ASSERT_FALSE(unknown.has_value());
  EXPECT_EQ(unknown.error(), "unknown option: --bogus");
  EXPECT_FALSE(parse_args({"ronfire", "--config"}).has_value());
  EXPECT_FALSE(parse_args({"ronfire", "--config="}).has_value());
  EXPECT_FALSE(parse_args({"ronfire", "/a", "/b"}).has_value());
}

// --- http --------------------------------------------------------------------

TEST(Http, StrictParsing) {
  const auto ok =
      parse_http_request("GET /a/b?x=1 HTTP/1.1\r\nHost: example\r\n\r\n");
  ASSERT_TRUE(ok.has_value());
  EXPECT_EQ(ok.value().path, "/a/b");
  EXPECT_EQ(ok.value().header("host"),
            std::optional<std::string>("example"));
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
  EXPECT_FALSE(parse_range_header("bytes=0-1,2-3").has_value());
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
