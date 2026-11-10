/**
 * @file http.h
 * @brief Strict HTTP/1.x parsing, request framing, ranges, and finalization.
 *
 * This module is the trust boundary for wire input. It accepts only
 * origin-form HTTP/1.0 and HTTP/1.1 requests, bounds header reads, rejects
 * request bodies and ambiguous transfer framing, and preserves buffered bytes
 * for pipelining. Handlers return buffered responses that are finalized here
 * for one byte range and HEAD semantics.
 */

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

/**
 * @brief Complete buffered HTTP response parts: status line, headers, body.
 *
 * The status line ends in CRLF and the header block ends in CRLFCRLF.
 */
struct HttpResponse {
  std::string status;
  std::string headers;
  std::vector<std::uint8_t> body;
};

/**
 * @brief One RFC-style byte range before resolution against a body length.
 */
struct ByteRangeSpec {
  std::optional<std::uint64_t> start;  ///< Inclusive start, or suffix range.
  std::optional<std::uint64_t> end;    ///< Inclusive end, or open-ended.
};

/**
 * @brief Parsed range state.
 *
 * Invalid and unsatisfiable ranges are distinguished from "no Range header"
 * so callers can return HTTP 416 correctly.
 */
struct RequestRange {
  enum class Kind { None, Single, Invalid };

  Kind kind = Kind::None;
  std::optional<ByteRangeSpec> spec;  ///< Set when kind == Single.
};

/**
 * @brief A parsed request line and header block.
 *
 * `path` is the query-free request path used for exact routing. GET and HEAD
 * requests intentionally reject all Content-Length and Transfer-Encoding
 * framing, so no body can be confused with a pipelined request.
 */
struct HttpRequest {
  std::string method;  ///< The HTTP method as received.
  std::string target;  ///< Original origin-form target, including the query.
  std::string path;    ///< Query-free path used for static/plugin routing.
  std::string version; ///< Accepted HTTP protocol version.
  std::vector<std::pair<std::string, std::string>> headers; ///< Wire order.
  RequestRange range;   ///< Parsed single-range request state.

  /**
   * @brief Returns the first header with a case-insensitive name.
   * @param name Header name to look up.
   * @return The header value, or std::nullopt when absent.
   */
  std::optional<std::string> header(const std::string& name) const;

  /**
   * @brief Computes persistence from every Connection header.
   * @return `close` always wins; otherwise HTTP/1.1 defaults to keep-alive
   *         and an explicit `keep-alive` token also keeps the connection open.
   */
  bool keep_alive() const;

  /**
   * @brief Reports whether the response must have HEAD semantics.
   * @return True when the method is HEAD (case-insensitive).
   */
  bool is_head() const;
};

/**
 * @brief Errors produced while reading or parsing a bounded request header
 * block.
 */
struct RequestReadError {
  enum class Kind { Io, HeaderTooLarge, Malformed, TimedOut };

  Kind kind = Kind::Malformed;
  runtime::IoError io{};
  std::string message;

  /**
   * @brief Builds an I/O read failure.
   * @param error The underlying IO error from the runtime.
   */
  static RequestReadError io_error(runtime::IoError error);

  /**
   * @brief Builds a header-size-cap failure.
   */
  static RequestReadError header_too_large();

  /**
   * @brief Builds a framing/grammar violation.
   * @param message Human-readable reason, used in logs and 400 handling.
   */
  static RequestReadError malformed(std::string message);

  /**
   * @brief Builds a deadline failure. The server turns this into HTTP 408.
   */
  static RequestReadError timed_out();
};

/**
 * @brief Maximum bytes consumed for one request's headers, including
 * delimiters.
 */
inline constexpr std::size_t kMaxRequestHeaderBytes = 16 * 1024;

/**
 * @brief Maximum time allowed to receive one complete request header block.
 */
inline constexpr auto kRequestIdleTimeout = std::chrono::seconds(30);

/**
 * @brief Buffered reader retaining pipelined bytes across calls.
 *
 * One instance backs one connection. The fd must be non-blocking.
 */
class BufferedReader {
 public:
  /**
   * @brief Wraps a non-blocking fd (not owned; caller closes it).
   * @param fd Non-blocking socket fd.
   */
  explicit BufferedReader(int fd);

  /**
   * @brief Reads exactly one CRLFCRLF-terminated request.
   *
   * Returns std::nullopt on a clean connection close with nothing buffered.
   * Leftover bytes stay buffered for the next call (pipelining).
   *
   * @param deadline Single absolute deadline for the whole header block, or
   *        std::nullopt to wait forever.
   * @return The parsed request, std::nullopt on clean EOF, or the read error.
   */
  runtime::Task<runtime::Expected<std::optional<HttpRequest>, RequestReadError>>
  read_next(std::optional<runtime::TimePoint> deadline);

  /**
   * @brief Returns unconsumed buffered bytes (for tests/debugging).
   */
  const std::string& buffered() const noexcept { return buffer_; }

  /**
   * @brief Appends bytes (for tests).
   * @param bytes Bytes to append to the buffer.
   */
  void append(std::string bytes) { buffer_ += bytes; }

 private:
  int fd_;
  std::string buffer_;
};

/**
 * @brief Parses one complete CRLF-terminated HTTP request header block.
 *
 * The parser is intentionally strict about framing: any Content-Length or
 * Transfer-Encoding on GET/HEAD is rejected before dispatch.
 *
 * @param bytes Complete header block ending in CRLFCRLF.
 * @return The parsed request, or a Malformed error with the reason.
 */
runtime::Expected<HttpRequest, RequestReadError> parse_http_request(
    const std::string& bytes);

/**
 * @brief Indicates that a `Range` header is not one valid byte range.
 *
 * This zero-sized error intentionally does not expose parser internals;
 * callers generally use it only to select an HTTP 416 response.
 */
struct RangeParseError {};

/**
 * @brief Parses a single `bytes=start-end`, `bytes=start-`, or suffix range.
 *
 * Multiple ranges are rejected because responses support one range only.
 *
 * @param value The raw Range header value.
 * @return The parsed spec, or RangeParseError.
 */
runtime::Expected<ByteRangeSpec, RangeParseError> parse_range_header(
    const std::string& value);

/**
 * @brief Applies range and HEAD semantics to a complete response.
 *
 * Successful (200) responses gain `Accept-Ranges: bytes`; satisfiable ranges
 * become 206, invalid/unsatisfiable ranges become 416, and HEAD keeps GET
 * headers (including a ranged Content-Length) without a body.
 *
 * @param response The handler-produced buffered response.
 * @param request The parsed request the response answers.
 * @return The finalized response ready for transport.
 */
HttpResponse finalize_response(HttpResponse response,
                               const HttpRequest& request);

}  // namespace ronfire
