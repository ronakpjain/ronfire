/** @file plugins/proxy.h @brief Fixed-target HTTP proxy plugin. */

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "plugins.h"
#include "runtime/io.h"
#include "runtime/task.h"

namespace ronfire::proxy {

/**
 * @brief Fixed-target proxy configuration from one plugin section.
 */
struct ProxyConfig {
  std::string route;                        ///< Exact local route path.
  std::string url;                          ///< Fixed http(s) upstream URL.
  std::string content_type;                 ///< Response Content-Type.
  std::optional<std::string> content_disposition; ///< Optional disposition.
  std::vector<std::string> redirect_hosts;  ///< Redirect host allowlist.
  std::uint64_t cache_seconds = 0;          ///< Body cache TTL (0 = off).
  std::uint64_t timeout_seconds = 0;        ///< Whole-fetch timeout.
  std::size_t max_bytes = 0;                ///< Incremental body limit.
};

/**
 * @brief Upstream timeout, size, status, and transport failures.
 */
struct ProxyError {
  enum class Kind { Timeout, Oversize, Request, Status };
  Kind kind = Kind::Request;
  std::string detail;   ///< For Request/Status message text.
  int status_code = 0;  ///< For Status.
  std::string status_text; ///< Reason phrase for Status.
  /** @brief Message used in the 502/504 error body. */
  std::string message() const;
};

/**
 * @brief Fetches one fixed HTTP URL (follows allowed redirects).
 *
 * HTTPS upstreams are rejected as Request errors: this build contains no
 * TLS implementation, so plain HTTP is the only transport it can fetch.
 */
runtime::Task<runtime::Expected<std::vector<std::uint8_t>, ProxyError>>
fetch(const std::string& url,
      const std::vector<std::string>& redirect_hosts, std::size_t max_bytes,
      runtime::TimePoint deadline);

/**
 * @brief Compiled proxy factory (registered as "proxy").
 */
class ProxyFactory : public PluginFactory {
 public:
  /**
   * @brief Builds one proxy handler from section fields.
   * @throws ConfigError on invalid fields.
   */
  std::shared_ptr<PluginHandler> build(
      const std::string& instance,
      const std::map<std::string, std::string>& fields) override;
};

}  // namespace ronfire::proxy
