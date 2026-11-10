/** @file test_plugins.cpp @brief Plugin config tests. */

#include "test_util.h"

using namespace testutil;

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


TEST(Plugins, MissingConfigPolicy) {
  ronfire::PluginRegistry registry;
  registry.register_plugin("test", std::make_shared<TestFactory>());
  std::string missing =
      (std::filesystem::temp_directory_path() / "ronfire-missing-xxxx.conf")
          .string();
  auto allowed = ronfire::RouteConfig::load(missing, registry, true);
  EXPECT_EQ(allowed.route_count(), 0);
  EXPECT_THROW(ronfire::RouteConfig::load(missing, registry, false),
               ronfire::ConfigError);
}
