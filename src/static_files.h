/** @file static_files.h @brief Secure document root + static responses. */

#pragma once

#include <optional>
#include <string>
#include <unordered_map>

#include "http.h"
#include "runtime/io.h"
#include "transport.h"

namespace ronfire {

/**
 * @brief Canonical document root enforcing containment and denied files.
 */
class DocumentRoot {
 public:
  /**
   * @brief Canonicalizes an existing directory.
   * @param root Document root directory.
   * @param denied Optional file to deny (canonicalized if it exists).
   * @return The root, or an error string.
   */
  static runtime::Expected<DocumentRoot, std::string> make(
      const std::string& root, const std::optional<std::string>& denied);

  /**
   * @brief Resolves a path with friendly fallbacks.
   * @param path Query-free request path.
   * @return Canonical file inside the root, or nullopt when denied/missing.
   *
   * Positive resolutions are cached: a miss always re-resolves, so new
   * files appear immediately, while repeated hits skip canonicalization.
   */
  std::optional<std::string> resolve(const std::string& path) const;

 private:
  std::string canonical_root_;
  std::optional<std::string> denied_;
  mutable std::unordered_map<std::string, std::string> cache_;
  /** @brief Full resolution (no caching); used by resolve(). */
  std::optional<std::string> ResolveOnce(const std::string& path) const;
};

/**
 * @brief Generates a static 200 response, or a local 404 on read failure.
 * @param full_path Canonical file path (from DocumentRoot::resolve).
 */
HttpResponse generate_response(const std::string& full_path);

/**
 * @brief Guesses Content-Type from a filename extension.
 * @param path File path.
 * @return MIME type (application/octet-stream when unknown).
 */
std::string guess_mime_type(const std::string& path);

/**
 * @brief Legacy compat: parses a raw request and returns its GET/HEAD path.
 * @param request Raw request bytes.
 * @param logger Optional logger for unsupported methods.
 */
std::optional<std::string> parse_request_path(
    const std::string& request, const AsyncLogger* logger = nullptr);

/**
 * @brief Legacy compat: resolves a raw request under the current directory.
 * @param request Raw request bytes.
 * @param logger Optional logger.
 */
std::optional<std::string> parse_request(const std::string& request,
                                         const AsyncLogger* logger = nullptr);

}  // namespace ronfire
