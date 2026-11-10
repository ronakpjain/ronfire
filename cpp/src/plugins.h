/** @file plugins.h @brief Compiled plugin registry, config, dispatch, cache. */

#pragma once

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "http.h"
#include "runtime/io.h"
#include "runtime/loop.h"
#include "runtime/task.h"

namespace ronfire {

/**
 * @brief Startup/configuration error with contextual section/line info.
 */
class ConfigError : public std::exception {
 public:
  /** @brief Creates an error with an explanation. */
  explicit ConfigError(std::string message) : message_(std::move(message)) {}
  /** @brief Returns the message. */
  const char* what() const noexcept override { return message_.c_str(); }

 private:
  std::string message_;
};

/**
 * @brief Request data passed across the plugin seam.
 */
struct PluginRequest {
  std::string method;                 ///< Request method (GET/HEAD).
  std::string target;                 ///< Original target incl. query.
  std::string path;                   ///< Query-free path for route lookup.
  std::vector<std::pair<std::string, std::string>> headers; ///< Wire headers.
  RequestRange range;                 ///< Parsed range state.
};

/**
 * @brief In-memory TTL cache shared by plugin handlers.
 *
 * Successful bodies are keyed by route; expired entries stay available as
 * stale data when upstream requests fail.
 */
class TtlCache {
 public:
  /**
   * @brief Returns a fresh (unexpired) cached body, if any.
   * @param key Cache key (route).
   */
  std::optional<std::vector<std::uint8_t>> fresh(const std::string& key) const;
  /**
   * @brief Returns any cached body (fresh or stale), if any.
   * @param key Cache key (route).
   */
  std::optional<std::vector<std::uint8_t>> stale(const std::string& key) const;
  /**
   * @brief Stores a body with a TTL.
   * @param key Cache key, @param body Body bytes, @param ttl Lifetime.
   */
  void put(std::string key, std::vector<std::uint8_t> body,
           std::chrono::seconds ttl);

 private:
  struct Entry {
    std::vector<std::uint8_t> body;
    runtime::TimePoint expires_at;
  };
  std::map<std::string, Entry> entries_;
};

/**
 * @brief A compiled-in plugin handler (trusted, in-process).
 */
class PluginHandler {
 public:
  virtual ~PluginHandler() = default;
  /** @brief The one absolute path owned by this instance. */
  virtual std::string route() const = 0;
  /**
   * @brief Handles one parsed request, returning a buffered response.
   * @param request Parsed request data.
   * @param cache Shared cache.
   */
  virtual runtime::Task<HttpResponse> dispatch(const PluginRequest& request,
                                               TtlCache& cache) = 0;
};

/**
 * @brief Builds configured plugin instances from section fields.
 */
class PluginFactory {
 public:
  virtual ~PluginFactory() = default;
  /**
   * @brief Builds one handler from an instance name and its fields.
   * @param instance Instance name.
   * @param fields Section fields (key = value).
   * @throws ConfigError on invalid fields.
   */
  virtual std::shared_ptr<PluginHandler> build(
      const std::string& instance,
      const std::map<std::string, std::string>& fields) = 0;
};

/**
 * @brief Registry of compiled plugin factories keyed by config name.
 */
class PluginRegistry {
 public:
  /**
   * @brief Registers one compiled factory under a plugin name.
   * @throws ConfigError on invalid/duplicate names.
   */
  void register_plugin(std::string name,
                       std::shared_ptr<PluginFactory> factory);
  /**
   * @brief Registers the built-in plugins enabled in this binary.
   * @throws ConfigError when a built-in fails.
   */
  static PluginRegistry with_builtins();
  /**
   * @brief Looks up a factory by name.
   * @param name Plugin name.
   */
  std::optional<std::shared_ptr<PluginFactory>> factory(
      const std::string& name) const;

 private:
  std::map<std::string, std::shared_ptr<PluginFactory>> factories_;
};

/**
 * @brief Exact-match dispatch: finds the route, awaits its handler, then
 * applies range/HEAD finalization.
 * @param routes Compiled route table.
 * @param request Parsed request.
 * @param cache Shared cache.
 * @return The finalized response, or nullopt when no route owns the path.
 */
runtime::Task<std::optional<HttpResponse>> dispatch_request(
    class RouteConfig& routes, const HttpRequest& request, TtlCache& cache);

/**
 * @brief Compiled route table produced by the registry.
 */
class RouteConfig {
 public:
  /**
   * @brief Parses using the built-in compiled registry.
   * @throws ConfigError with a line-numbered message on failure.
   */
  static RouteConfig parse(const std::string& contents);
  /**
   * @brief Parses sections, delegating each instance to its factory.
   * @throws ConfigError with a line-numbered message on failure.
   */
  static RouteConfig parse_with_registry(
      const std::string& contents, const PluginRegistry& registry);
  /**
   * @brief Loads a config file; missing is OK only when `missing_allowed`.
   * @throws ConfigError on read/parse failures.
   */
  static RouteConfig load(const std::string& path,
                          const PluginRegistry& registry,
                          bool missing_allowed);
  /**
   * @brief Finds a route by exact path.
   * @param path Query-free request path.
   */
  std::optional<std::shared_ptr<PluginHandler>> route_for(
      const std::string& path) const;
  /**
   * @brief Number of registered routes (tests).
   */
  std::size_t route_count() const { return routes_.size(); }

 private:
  struct RegisteredRoute {
    std::string path;
    std::shared_ptr<PluginHandler> handler;
  };
  std::vector<RegisteredRoute> routes_;
  friend runtime::Task<std::optional<HttpResponse>> dispatch_request(
      RouteConfig&, const HttpRequest&, TtlCache&);
};

/**
 * @brief Validates a proxy route path (absolute, no traversal).
 * @param path Route path.
 * @throws ConfigError on invalid paths.
 */
void validate_route_path(const std::string& path);

/**
 * @brief Validates a response header value (no control characters).
 * @param value Header value.
 * @throws ConfigError on invalid values.
 */
void validate_header_value(const std::string& value);

}  // namespace ronfire
