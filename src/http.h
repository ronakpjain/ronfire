/** @file http.h @brief Strict HTTP/1.x parsing, framing, ranges, finalization. */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "runtime/io.h"
#include "runtime/loop.h"
#include "runtime/task.h"

namespace ronfire {

/** @brief Buffered response: status line, headers, body. */
struct HttpResponse {
  std::string status;
  std::string headers;
  std::vector<std::uint8_t> body;
};

/** @brief One byte range before length resolution. */
struct ByteRangeSpec {
  std::optional<std::uint64_t> start;  ///< Inclusive start, or suffix range.
  std::optional<std::uint64_t> end;    ///< Inclusive end, or open-ended.
};

/** @brief Range state (None/Single/Invalid). */
struct RequestRange {
  enum class Kind { None, Single, Invalid };

  Kind kind = Kind::None;
  std::optional<ByteRangeSpec> spec;  ///< Set when kind == Single.
};

/** @brief Parsed request; path is query-free, framing is strict (no bodies). */
struct HttpRequest {
  std::string method;  ///< The HTTP method as received.
  std::string target;  ///< Original origin-form target, including the query.
  std::string path;    ///< Query-free path used for static/plugin routing.
  std::string version; ///< Accepted HTTP protocol version.
  std::vector<std::pair<std::string, std::string>> headers; ///< Wire order.
  RequestRange range;   ///< Parsed single-range request state.

  /** @brief First header with this (case-insensitive) name, if any. */
  std::optional<std::string> header(const std::string& name) const;

  /** @brief Persistence; close wins, else HTTP/1.1/keep-alive. */
  bool keep_alive() const;

  /** @brief True for HEAD. */
  bool is_head() const;
};

/** @brief Read/parse failure for one header block. */
struct RequestReadError {
  enum class Kind { Io, HeaderTooLarge, Malformed, TimedOut };

  Kind kind = Kind::Malformed;
  runtime::IoError io{};
  std::string message;

  /** @brief I/O failure. */
  static RequestReadError io_error(runtime::IoError error);

  /** @brief Header-size-cap failure. */
  static RequestReadError header_too_large();

  /** @brief Framing violation with reason. */
  static RequestReadError malformed(std::string message);

  /** @brief Deadline failure (server maps to 408). */
  static RequestReadError timed_out();
};

/** @brief Max request header bytes (incl. delimiters). */
inline constexpr std::size_t kMaxRequestHeaderBytes = 16 * 1024;

/** @brief Max time for one complete header block. */
inline constexpr auto kRequestIdleTimeout = std::chrono::seconds(30);

/** @brief Per-connection reader retaining pipelined bytes. */
class BufferedReader {
 public:
  /** @brief Wraps a non-blocking fd (not owned). */
  explicit BufferedReader(int fd);

  /** @brief Reads one request, or nullopt on clean EOF. */
  runtime::Task<runtime::Expected<std::optional<HttpRequest>, RequestReadError>>
  read_next(std::optional<runtime::TimePoint> deadline);

  /** @brief Unconsumed buffered bytes. */
  const std::string& buffered() const noexcept { return buffer_; }

  /** @brief Appends bytes (tests). */
  void append(std::string bytes) { buffer_ += bytes; }

 private:
  int fd_;
  std::string buffer_;
};

/** @brief Parses one complete header block (rejects CL/TE, traversal). */
runtime::Expected<HttpRequest, RequestReadError> parse_http_request(
    const std::string& bytes);

/** @brief Invalid Range marker (callers map to 416). */
struct RangeParseError {};

/** @brief Parses one byte range; multiple ranges rejected. */
runtime::Expected<ByteRangeSpec, RangeParseError> parse_range_header(
    const std::string& value);

/** @brief Applies range/HEAD semantics (200->206/416, HEAD drops body). */
HttpResponse finalize_response(HttpResponse response,
                               const HttpRequest& request);

}  // namespace ronfire
