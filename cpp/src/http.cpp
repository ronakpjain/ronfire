/** @file http.cpp @brief HTTP implementation (see http.h). */

#include "http.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace ronfire {
namespace {

constexpr std::string_view kTerminator = "\r\n\r\n";

bool ToLowerAscii(char c) {
  return static_cast<char>((c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c);
}

bool EqIgnoreCase(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (ToLowerAscii(a[i]) != ToLowerAscii(b[i])) {
      return false;
    }
  }
  return true;
}

bool IsAsciiWs(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
         c == '\v';
}

std::string Trim(const std::string& s) {
  std::size_t start = 0;
  while (start < s.size() && IsAsciiWs(s[start])) {
    ++start;
  }
  std::size_t end = s.size();
  while (end > start && IsAsciiWs(s[end - 1])) {
    --end;
  }
  return s.substr(start, end - start);
}

std::vector<std::string> Split(const std::string& s, const std::string& delim) {
  std::vector<std::string> parts;
  std::size_t at = 0;
  for (;;) {
    const std::size_t found = s.find(delim, at);
    if (found == std::string::npos) {
      parts.push_back(s.substr(at));
      return parts;
    }
    parts.push_back(s.substr(at, found - at));
    at = found + delim.size();
  }
}

std::vector<std::string> SplitWhitespace(const std::string& s) {
  std::vector<std::string> parts;
  std::size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && IsAsciiWs(s[i])) {
      ++i;
    }
    if (i >= s.size()) {
      break;
    }
    std::size_t end = i;
    while (end < s.size() && !IsAsciiWs(s[end])) {
      ++end;
    }
    parts.push_back(s.substr(i, end - i));
    i = end;
  }
  return parts;
}

bool IsValidUtf8(const std::string& s) {
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(s.data());
  std::size_t i = 0;
  while (i < s.size()) {
    const std::uint8_t lead = bytes[i];
    if (lead < 0x80) {
      ++i;
      continue;
    }
    std::size_t length = 0;
    std::uint32_t minimum = 0;
    std::uint32_t codepoint = 0;
    if (lead >= 0xC2 && lead <= 0xDF) {
      length = 2;
      minimum = 0x80;
      codepoint = lead & 0x1F;
    } else if (lead >= 0xE0 && lead <= 0xEF) {
      length = 3;
      minimum = 0x800;
      codepoint = lead & 0x0F;
    } else if (lead >= 0xF0 && lead <= 0xF4) {
      length = 4;
      minimum = 0x10000;
      codepoint = lead & 0x07;
    } else {
      return false;
    }
    if (i + length > s.size()) {
      return false;
    }
    for (std::size_t k = 1; k < length; ++k) {
      const std::uint8_t cont = bytes[i + k];
      if (cont < 0x80 || cont > 0xBF) {
        return false;
      }
      codepoint = (codepoint << 6) | (cont & 0x3F);
    }
    if (codepoint < minimum || codepoint > 0x10FFFF ||
        (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
      return false;
    }
    i += length;
  }
  return true;
}

bool IsHeaderToken(const std::string& value) {
  if (value.empty()) {
    return false;
  }
  static constexpr std::string_view kSpecials = "!#$%&'*+-.^_`|~";
  for (char c : value) {
    const bool alnum = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                       (c >= 'a' && c <= 'z');
    if (!alnum && kSpecials.find(c) == std::string_view::npos) {
      return false;
    }
  }
  return true;
}

bool ParseU64(const std::string& digits, std::uint64_t& out) {
  if (digits.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  for (char c : digits) {
    if (c < '0' || c > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
      return false;
    }
    value = value * 10 + digit;
  }
  out = value;
  return true;
}

std::string SetHeader(const std::string& headers, const std::string& name,
                      const std::string& value) {
  std::vector<std::string> lines;
  for (const auto& line : Split(headers, "\r\n")) {
    if (line.empty()) {
      continue;
    }
    const std::size_t colon = line.find(':');
    if (colon != std::string::npos &&
        EqIgnoreCase(Trim(line.substr(0, colon)), name)) {
      continue;
    }
    lines.push_back(line);
  }
  std::string joined;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (i != 0) {
      joined += "\r\n";
    }
    joined += lines[i];
  }
  if (!lines.empty()) {
    joined += "\r\n";
  }
  joined += name;
  joined += ": ";
  joined += value;
  joined += "\r\n\r\n";
  return joined;
}

std::vector<std::uint8_t> ToBytes(const std::string& s) {
  return std::vector<std::uint8_t>(s.begin(), s.end());
}

}  // namespace

std::optional<std::string> HttpRequest::header(const std::string& name) const {
  for (const auto& [key, value] : headers) {
    if (EqIgnoreCase(key, name)) {
      return value;
    }
  }
  return std::nullopt;
}

bool HttpRequest::keep_alive() const {
  bool has_close = false;
  bool has_keep_alive = false;
  for (const auto& [key, value] : headers) {
    if (!EqIgnoreCase(key, "connection")) {
      continue;
    }
    for (const auto& token : Split(value, ",")) {
      const std::string trimmed = Trim(token);
      if (EqIgnoreCase(trimmed, "close")) {
        has_close = true;
      } else if (EqIgnoreCase(trimmed, "keep-alive")) {
        has_keep_alive = true;
      }
    }
  }
  if (has_close) {
    return false;
  }
  return has_keep_alive || version == "HTTP/1.1";
}

bool HttpRequest::is_head() const { return EqIgnoreCase(method, "HEAD"); }

RequestReadError RequestReadError::io_error(runtime::IoError error) {
  RequestReadError result;
  result.kind = Kind::Io;
  result.io = error;
  return result;
}

RequestReadError RequestReadError::header_too_large() {
  RequestReadError result;
  result.kind = Kind::HeaderTooLarge;
  return result;
}

RequestReadError RequestReadError::malformed(std::string message) {
  RequestReadError result;
  result.kind = Kind::Malformed;
  result.message = std::move(message);
  return result;
}

RequestReadError RequestReadError::timed_out() {
  RequestReadError result;
  result.kind = Kind::TimedOut;
  return result;
}

BufferedReader::BufferedReader(int fd) : fd_(fd) {}

runtime::Task<runtime::Expected<std::optional<HttpRequest>, RequestReadError>>
BufferedReader::read_next(std::optional<runtime::TimePoint> deadline) {
  using Result =
      runtime::Expected<std::optional<HttpRequest>, RequestReadError>;
  for (;;) {
    // A terminator only wins when it completes within the header budget;
    // that is what the byte-at-a-time Rust reader does.
    const std::size_t pos = buffer_.find(kTerminator);
    if (pos != std::string::npos && pos + kTerminator.size() <= kMaxRequestHeaderBytes) {
      const std::string block = buffer_.substr(0, pos + kTerminator.size());
      buffer_.erase(0, pos + kTerminator.size());
      auto parsed = parse_http_request(block);
      if (parsed.has_value()) {
        co_return Result::ok(std::optional<HttpRequest>(std::move(parsed.value())));
      }
      co_return Result::fail(parsed.error());
    }
    if (buffer_.size() >= kMaxRequestHeaderBytes) {
      co_return Result::fail(RequestReadError::header_too_large());
    }
    char chunk[4096];
    auto got = co_await runtime::read_once(fd_, chunk, sizeof(chunk), deadline);
    if (!got.has_value()) {
      if (got.error().timed_out) {
        co_return Result::fail(RequestReadError::timed_out());
      }
      co_return Result::fail(RequestReadError::io_error(got.error()));
    }
    if (got.value() == 0) {
      if (buffer_.empty()) {
        co_return Result::ok(std::nullopt);
      }
      co_return Result::fail(RequestReadError::malformed(
          "connection closed before request headers completed"));
    }
    buffer_.append(chunk, static_cast<std::size_t>(got.value()));
  }
}

runtime::Expected<HttpRequest, RequestReadError> parse_http_request(
    const std::string& bytes) {
  using Result = runtime::Expected<HttpRequest, RequestReadError>;
  if (!IsValidUtf8(bytes)) {
    return Result::fail(
        RequestReadError::malformed("request is not UTF-8 headers"));
  }
  if (bytes.size() < kTerminator.size() ||
      bytes.substr(bytes.size() - kTerminator.size()) != kTerminator) {
    return Result::fail(RequestReadError::malformed(
        "request headers must end with CRLFCRLF"));
  }
  const std::string header_block =
      bytes.substr(0, bytes.size() - kTerminator.size());
  const std::vector<std::string> lines = Split(header_block, "\r\n");
  if (lines.empty() || lines[0].empty()) {
    return Result::fail(
        RequestReadError::malformed("missing request line"));
  }
  const std::vector<std::string> parts = SplitWhitespace(lines[0]);
  if (parts.size() != 3) {
    return Result::fail(
        RequestReadError::malformed("malformed request line"));
  }
  HttpRequest request;
  request.method = parts[0];
  request.target = parts[1];
  request.version = parts[2];
  if (request.version != "HTTP/1.0" && request.version != "HTTP/1.1") {
    return Result::fail(
        RequestReadError::malformed("unsupported HTTP version"));
  }
  const std::string& target = request.target;
  if (target.empty() || target.front() != '/' ||
      target.find_first_of("#\\\0") != std::string::npos) {
    return Result::fail(
        RequestReadError::malformed("invalid request target"));
  }
  const std::size_t query = target.find('?');
  request.path =
      query == std::string::npos ? target : target.substr(0, query);
  if (request.path.empty()) {
    return Result::fail(
        RequestReadError::malformed("invalid or traversing path"));
  }
  for (const auto& part : Split(request.path, "/")) {
    if (part == "..") {
      return Result::fail(
          RequestReadError::malformed("invalid or traversing path"));
    }
  }

  for (std::size_t i = 1; i < lines.size(); ++i) {
    const std::string& line = lines[i];
    const std::size_t colon = line.find(':');
    if (colon == std::string::npos) {
      return Result::fail(
          RequestReadError::malformed("malformed header"));
    }
    const std::string name = Trim(line.substr(0, colon));
    const std::string value = Trim(line.substr(colon + 1));
    bool bad_value = false;
    for (char c : value) {
      const auto byte = static_cast<unsigned char>(c);
      if (byte < 0x20 && byte != '\t') {
        bad_value = true;
        break;
      }
    }
    if (!IsHeaderToken(name) || bad_value) {
      return Result::fail(
          RequestReadError::malformed("invalid header"));
    }
    request.headers.emplace_back(name, value);
  }

  std::vector<std::string> ranges;
  for (const auto& [name, value] : request.headers) {
    if (EqIgnoreCase(name, "range")) {
      ranges.push_back(value);
    }
  }
  if (ranges.empty()) {
    request.range.kind = RequestRange::Kind::None;
  } else if (ranges.size() == 1) {
    auto parsed = parse_range_header(ranges.front());
    if (parsed.has_value()) {
      request.range.kind = RequestRange::Kind::Single;
      request.range.spec = parsed.value();
    } else {
      request.range.kind = RequestRange::Kind::Invalid;
    }
  } else {
    request.range.kind = RequestRange::Kind::Invalid;
  }

  if (request.header("transfer-encoding").has_value()) {
    return Result::fail(RequestReadError::malformed(
        "transfer-encoding is not supported"));
  }
  for (const auto& [name, value] : request.headers) {
    (void)value;
    if (EqIgnoreCase(name, "content-length")) {
      return Result::fail(RequestReadError::malformed(
          "GET and HEAD bodies or content-length framing are not supported"));
    }
  }
  return Result::ok(std::move(request));
}

runtime::Expected<ByteRangeSpec, RangeParseError> parse_range_header(
    const std::string& value) {
  using Result = runtime::Expected<ByteRangeSpec, RangeParseError>;
  constexpr std::string_view kPrefix = "bytes=";
  if (value.rfind(kPrefix, 0) != 0) {
    return Result::fail(RangeParseError{});
  }
  const std::string rest = value.substr(kPrefix.size());
  if (rest.empty() || rest.find(',') != std::string::npos) {
    return Result::fail(RangeParseError{});
  }
  for (char c : rest) {
    if (IsAsciiWs(c)) {
      return Result::fail(RangeParseError{});
    }
  }
  const std::size_t dash = rest.find('-');
  if (dash == std::string::npos) {
    return Result::fail(RangeParseError{});
  }
  const std::string start = rest.substr(0, dash);
  const std::string end = rest.substr(dash + 1);
  if (start.empty() && end.empty()) {
    return Result::fail(RangeParseError{});
  }
  ByteRangeSpec spec;
  if (start.empty()) {
    std::uint64_t suffix = 0;
    if (!ParseU64(end, suffix) || suffix == 0) {
      return Result::fail(RangeParseError{});
    }
    spec.start = std::nullopt;
    spec.end = suffix;
    return Result::ok(spec);
  }
  std::uint64_t parsed_start = 0;
  if (!ParseU64(start, parsed_start)) {
    return Result::fail(RangeParseError{});
  }
  spec.start = parsed_start;
  if (end.empty()) {
    spec.end = std::nullopt;
    return Result::ok(spec);
  }
  std::uint64_t parsed_end = 0;
  if (!ParseU64(end, parsed_end) || parsed_end < parsed_start) {
    return Result::fail(RangeParseError{});
  }
  spec.end = parsed_end;
  return Result::ok(spec);
}

namespace {

std::optional<std::pair<std::size_t, std::size_t>> ResolvedRange(
    const ByteRangeSpec& spec, std::size_t length) {
  if (length == 0) {
    return std::nullopt;
  }
  const std::uint64_t len = static_cast<std::uint64_t>(length);
  std::uint64_t start = 0;
  std::uint64_t end = 0;
  if (spec.start.has_value() && spec.end.has_value()) {
    start = *spec.start;
    end = std::min<std::uint64_t>(*spec.end, len - 1);
  } else if (spec.start.has_value()) {
    start = *spec.start;
    end = len - 1;
  } else if (spec.end.has_value()) {
    const std::uint64_t suffix = *spec.end;
    start = suffix < len ? len - suffix : 0;
    end = len - 1;
  } else {
    return std::nullopt;
  }
  if (start >= len || start > end) {
    return std::nullopt;
  }
  return std::make_pair(static_cast<std::size_t>(start),
                        static_cast<std::size_t>(end));
}

HttpResponse RangeError(const std::string& headers, std::size_t original_length,
                        bool head) {
  HttpResponse response;
  response.status = "HTTP/1.1 416 Range Not Satisfiable\r\n";
  response.body = ToBytes("<h1>416 Range Not Satisfiable</h1>");
  response.headers = SetHeader(headers, "Content-Range",
                               "bytes */" + std::to_string(original_length));
  response.headers = SetHeader(response.headers, "Content-Length",
                               std::to_string(response.body.size()));
  if (head) {
    response.body.clear();
  }
  return response;
}

}  // namespace

HttpResponse finalize_response(HttpResponse response,
                               const HttpRequest& request) {
  const std::size_t original_length = response.body.size();
  const bool successful = response.status.rfind("HTTP/1.1 200 ", 0) == 0;
  if (successful) {
    response.headers = SetHeader(response.headers, "Accept-Ranges", "bytes");
  }
  if (successful) {
    if (request.range.kind == RequestRange::Kind::Invalid) {
      HttpResponse error =
          RangeError(response.headers, original_length, false);
      response.headers = error.headers;
      response.status = error.status;
      response.body = error.body;
      // The shared HEAD handling below clears the body for HEAD.
    } else if (request.range.kind == RequestRange::Kind::Single &&
               request.range.spec.has_value()) {
      const auto resolved = ResolvedRange(*request.range.spec, original_length);
      if (!resolved.has_value()) {
        return RangeError(response.headers, original_length,
                          request.is_head());
      }
      const auto [start, end] = *resolved;
      response.status = "HTTP/1.1 206 Partial Content\r\n";
      response.body = std::vector<std::uint8_t>(
          response.body.begin() + static_cast<std::ptrdiff_t>(start),
          response.body.begin() + static_cast<std::ptrdiff_t>(end) + 1);
      response.headers =
          SetHeader(response.headers, "Content-Range",
                    "bytes " + std::to_string(start) + "-" +
                        std::to_string(end) + "/" +
                        std::to_string(original_length));
      response.headers = SetHeader(response.headers, "Content-Length",
                                   std::to_string(response.body.size()));
    } else {
      response.headers = SetHeader(response.headers, "Content-Length",
                                   std::to_string(original_length));
    }
  }
  if (request.is_head()) {
    response.body.clear();
  }
  return response;
}

}  // namespace ronfire
