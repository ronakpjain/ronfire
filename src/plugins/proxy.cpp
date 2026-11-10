/** @file plugins/proxy.cpp @brief Proxy plugin implementation. */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "plugins/proxy.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

namespace ronfire::proxy {
namespace {

constexpr std::size_t kMaxHeaderBytes = 64 * 1024;

std::string ToLower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') {
      c = static_cast<char>(c + ('a' - 'A'));
    }
  }
  return s;
}

bool EqIgnoreCase(const std::string& a, const std::string& b) {
  return ToLower(a) == ToLower(b);
}

struct UrlParts {
  std::string scheme;  // http or https
  std::string host;    // lowercased, brackets stripped
  std::string port_str; // original port text ("" = default)
  std::string target;  // path + query (default "/")
};

// Validates per the factory contract: http/https, host present, no userinfo.
std::optional<UrlParts> ParseUrl(const std::string& value) {
  for (char c : value) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte <= 0x20 || byte == 0x7f) {
      return std::nullopt;
    }
  }
  const std::size_t scheme_end = value.find("://");
  if (scheme_end == std::string::npos) {
    return std::nullopt;
  }
  UrlParts parts;
  parts.scheme = ToLower(value.substr(0, scheme_end));
  if (parts.scheme != "http" && parts.scheme != "https") {
    return std::nullopt;
  }
  const std::string rest = value.substr(scheme_end + 3);
  const std::size_t authority_end = rest.find_first_of("/?#");
  const std::string authority =
      rest.substr(0, authority_end == std::string::npos ? rest.size()
                                                         : authority_end);
  if (authority.empty() || authority.find('@') != std::string::npos) {
    return std::nullopt;
  }
  std::string hostport;
  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string::npos) {
      return std::nullopt;
    }
    parts.host = ToLower(authority.substr(1, close - 1));
    hostport = authority.substr(close + 1);
    if (!hostport.empty() && hostport.front() != ':') {
      return std::nullopt;
    }
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon == std::string::npos) {
      parts.host = ToLower(authority);
    } else {
      parts.host = ToLower(authority.substr(0, colon));
      hostport = authority.substr(colon);
    }
  }
  if (parts.host.empty()) {
    return std::nullopt;
  }
  if (!hostport.empty()) {
    parts.port_str = hostport.substr(1);
    if (parts.port_str.empty() ||
        parts.port_str.find_first_not_of("0123456789") != std::string::npos) {
      return std::nullopt;
    }
    const long port = std::stol(parts.port_str);
    if (port < 0 || port > 65535) {
      return std::nullopt;
    }
  }
  std::string target = "/";
  if (authority_end != std::string::npos) {
    const std::string tail = rest.substr(authority_end);
    if (tail.front() == '/') {
      const std::size_t hash = tail.find('#');
      target = tail.substr(0, hash == std::string::npos ? tail.size() : hash);
    } else if (tail.front() == '?') {
      const std::size_t hash = tail.find('#');
      const std::string query =
          tail.substr(0, hash == std::string::npos ? tail.size() : hash);
      target = "/" + query;
    }
  }
  if (target.empty()) {
    target = "/";
  }
  parts.target = target;
  return parts;
}

std::string DefaultPort(const std::string& scheme) {
  return scheme == "https" ? "443" : "80";
}

std::string ReasonPhrase(int code) {
  switch (code) {
    case 200: return "OK";
    case 204: return "No Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 410: return "Gone";
    case 429: return "Too Many Requests";
    case 500: return "Internal Server Error";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return "<unknown status code>";
  }
}

ProxyError RequestFailed(const std::string& detail) {
  ProxyError error;
  error.kind = ProxyError::Kind::Request;
  error.detail = detail;
  return error;
}

ProxyError StatusFailed(int code) {
  ProxyError error;
  error.kind = ProxyError::Kind::Status;
  error.status_code = code;
  error.status_text = ReasonPhrase(code);
  return error;
}

std::uint64_t ParseInteger(const std::map<std::string, std::string>& fields,
                           const std::string& name, bool allow_zero) {
  const auto it = fields.find(name);
  if (it == fields.end()) {
    throw ConfigError("missing proxy field: " + name);
  }
  const std::string& text = it->second;
  if (text.empty() ||
      text.find_first_not_of("0123456789") != std::string::npos) {
    throw ConfigError("proxy field " + name +
                      " must be a non-negative integer");
  }
  std::uint64_t value = 0;
  for (char c : text) {
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) {
      throw ConfigError("proxy field " + name + " is too large");
    }
    value = value * 10 + digit;
  }
  if (!allow_zero && value == 0) {
    throw ConfigError("proxy field " + name + " must be greater than zero");
  }
  return value;
}

std::string ValidateHost(const std::string& host) {
  if (host.empty() || host.size() > 253) {
    throw ConfigError("invalid redirect host: \"" + host + "\"");
  }
  for (char c : host) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') || c == '.' || c == '-';
    if (!ok) {
      throw ConfigError("invalid redirect host: \"" + host + "\"");
    }
  }
  if (host.front() == '.' || host.back() == '.' ||
      host.find("..") != std::string::npos) {
    throw ConfigError("invalid redirect host: \"" + host + "\"");
  }
  return ToLower(host);
}

std::vector<std::string> ParseRedirectHosts(
    const std::map<std::string, std::string>& fields,
    const std::string& original_host) {
  const auto it = fields.find("redirect_hosts");
  if (it == fields.end() || it->second.empty()) {
    return {ToLower(original_host)};
  }
  std::vector<std::string> hosts;
  std::size_t at = 0;
  for (;;) {
    const std::size_t comma = it->second.find(',', at);
    std::string piece = it->second.substr(
        at, comma == std::string::npos ? comma : comma - at);
    // Trim ASCII spaces.
    const std::size_t start = piece.find_first_not_of(" \t");
    piece = start == std::string::npos ? std::string() : piece.substr(start);
    const std::size_t end = piece.find_last_not_of(" \t");
    if (end != std::string::npos) {
      piece = piece.substr(0, end + 1);
    }
    hosts.push_back(ValidateHost(piece));
    if (comma == std::string::npos) {
      break;
    }
    at = comma + 1;
  }
  if (hosts.empty()) {
    throw ConfigError("redirect_hosts must not be empty");
  }
  return hosts;
}

struct FetchResult {
  int status = 0;
  std::string location;
  std::vector<std::uint8_t> body;
};

/**
 * @brief TLS channel over a connected TCP fd (OpenSSL).
 */
struct TlsChannel {
  int fd = -1;
  SSL_CTX* ctx = nullptr;
  SSL* ssl = nullptr;
  ~TlsChannel() {
    if (ssl != nullptr) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    if (ctx != nullptr) {
      SSL_CTX_free(ctx);
    }
    if (fd >= 0) {
      ::close(fd);
    }
  }
  TlsChannel() = default;
  TlsChannel(const TlsChannel&) = delete;
  TlsChannel& operator=(const TlsChannel&) = delete;
  TlsChannel(TlsChannel&& other) noexcept
      : fd(std::exchange(other.fd, -1)),
        ctx(std::exchange(other.ctx, nullptr)),
        ssl(std::exchange(other.ssl, nullptr)) {}
};

/**
 * @brief Runs the TLS handshake (SNI + verification) under a deadline.
 * @param fd Connected fd.
 * @param parts Host for SNI/verification.
 * @param deadline Fetch deadline.
 * @return The channel, or the proxy error.
 */
runtime::Task<runtime::Expected<std::shared_ptr<TlsChannel>, ProxyError>>
OpenTlsChannel(int fd, const UrlParts& parts, runtime::TimePoint deadline) {
  using Result = runtime::Expected<std::shared_ptr<TlsChannel>, ProxyError>;
  auto channel = std::make_shared<TlsChannel>();
  channel->ctx = SSL_CTX_new(TLS_client_method());
  if (channel->ctx == nullptr) {
    channel->fd = -1;
    co_return Result::fail(RequestFailed("TLS context setup failed"));
  }
  SSL_CTX_set_verify(channel->ctx, SSL_VERIFY_PEER, nullptr);
  if (SSL_CTX_set_default_verify_paths(channel->ctx) != 1) {
    channel->fd = -1;
    co_return Result::fail(RequestFailed("TLS trust store setup failed"));
  }
  channel->ssl = SSL_new(channel->ctx);
  if (channel->ssl == nullptr) {
    channel->fd = -1;
    co_return Result::fail(RequestFailed("TLS session setup failed"));
  }
  SSL_set_fd(channel->ssl, fd);
  SSL_set_tlsext_host_name(channel->ssl, parts.host.c_str());
  for (;;) {
    const int rc = SSL_connect(channel->ssl);
    if (rc == 1) {
      break;
    }
    const int err = SSL_get_error(channel->ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      const bool timed_out = co_await runtime::ReadyAwaitable{
          fd, static_cast<short>(err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), deadline};
      if (timed_out) {
        ProxyError error;
        error.kind = ProxyError::Kind::Timeout;
        channel->fd = -1;
        co_return Result::fail(error);
      }
      continue;
    }
    channel->fd = -1;
    co_return Result::fail(RequestFailed("TLS handshake failed"));
  }
  if (SSL_get_verify_result(channel->ssl) != X509_V_OK) {
    channel->fd = -1;
  co_return Result::fail(RequestFailed("TLS certificate verification failed"));
  }
  channel->fd = fd;
  co_return Result::ok(channel);
}

/**
 * @brief Buffered fetch reader with a single deadline (fd or TLS).
 */
struct FetchReader {
  int fd;
  runtime::TimePoint deadline;
  std::string buffer;
  std::shared_ptr<TlsChannel> tls;  // empty for plain HTTP

  /** @brief Reads more bytes; nullopt on EOF, error on failure/timeout. */
  runtime::Task<runtime::Expected<bool, ProxyError>> fill() {
    using Result = runtime::Expected<bool, ProxyError>;
    char chunk[4096];
    if (tls != nullptr) {
      for (;;) {
        const int n = SSL_read(tls->ssl, chunk, sizeof(chunk));
        if (n > 0) {
          buffer.append(chunk, static_cast<std::size_t>(n));
          co_return Result::ok(true);
        }
        const int err = SSL_get_error(tls->ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
          const bool timed_out = co_await runtime::ReadyAwaitable{
              fd, static_cast<short>(err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), deadline};
          if (timed_out) {
            ProxyError error;
            error.kind = ProxyError::Kind::Timeout;
            co_return Result::fail(error);
          }
          continue;
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
          co_return Result::ok(false);
        }
        co_return Result::fail(RequestFailed("TLS read failed"));
      }
    }
    auto got = co_await runtime::read_once(fd, chunk, sizeof(chunk), deadline);
    if (!got.has_value()) {
      if (got.error().timed_out) {
        ProxyError error;
        error.kind = ProxyError::Kind::Timeout;
        co_return runtime::Expected<bool, ProxyError>::fail(error);
      }
      co_return runtime::Expected<bool, ProxyError>::fail(
          RequestFailed(std::strerror(got.error().err)));
    }
    if (got.value() == 0) {
      co_return runtime::Expected<bool, ProxyError>::ok(false);
    }
    buffer.append(chunk, static_cast<std::size_t>(got.value()));
    co_return runtime::Expected<bool, ProxyError>::ok(true);
  }

  /**
   * @brief Finds CRLFCRLF, reading more as needed.
   * @return Header end index, or nullopt (error/oversize already reported).
   */
  runtime::Task<runtime::Expected<std::size_t, ProxyError>> find_headers() {
    using Result = runtime::Expected<std::size_t, ProxyError>;
    for (;;) {
      const std::size_t pos = buffer.find("\r\n\r\n");
      if (pos != std::string::npos) {
        co_return Result::ok(pos);
      }
      if (buffer.size() > kMaxHeaderBytes) {
        co_return Result::fail(
            RequestFailed("upstream response headers too large"));
      }
      auto more = co_await fill();
      if (!more.has_value()) {
        co_return Result::fail(more.error());
      }
      if (!more.value()) {
        co_return Result::fail(RequestFailed(
            "connection closed before response headers completed"));
      }
    }
  }

  /** @brief Reads one CRLF-terminated line (without it). */
  runtime::Task<runtime::Expected<std::string, ProxyError>> read_line() {
    using Result = runtime::Expected<std::string, ProxyError>;
    for (;;) {
      const std::size_t pos = buffer.find("\r\n");
      if (pos != std::string::npos) {
        std::string line = buffer.substr(0, pos);
        buffer.erase(0, pos + 2);
        co_return Result::ok(line);
      }
      if (buffer.size() > kMaxHeaderBytes) {
        co_return Result::fail(
            RequestFailed("upstream response headers too large"));
      }
      auto more = co_await fill();
      if (!more.has_value()) {
        co_return Result::fail(more.error());
      }
      if (!more.value()) {
        co_return Result::fail(
            RequestFailed("connection closed before response body completed"));
      }
    }
  }
};

/**
 * @brief Connects to host:port (resolves via getaddrinfo once).
 * @return Connected fd, or failure.
 */
runtime::Task<runtime::Expected<int, ProxyError>> Connect(
    const UrlParts& parts, runtime::TimePoint deadline) {
  using Result = runtime::Expected<int, ProxyError>;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* list = nullptr;
  const std::string port =
      parts.port_str.empty() ? DefaultPort(parts.scheme) : parts.port_str;
  if (::getaddrinfo(parts.host.c_str(), port.c_str(), &hints, &list) != 0) {
    co_return Result::fail(
        RequestFailed("cannot resolve upstream host: " + parts.host));
  }
  int last_error = ECONNREFUSED;
  for (const addrinfo* item = list; item != nullptr; item = item->ai_next) {
    const int fd = ::socket(item->ai_family, item->ai_socktype, item->ai_protocol);
    if (fd < 0) {
      last_error = errno;
      continue;
    }
    runtime::set_nonblocking(fd);
    if (::connect(fd, item->ai_addr, item->ai_addrlen) == 0) {
      ::freeaddrinfo(list);
      co_return Result::ok(fd);
    }
    if (errno != EINPROGRESS) {
      last_error = errno;
      ::close(fd);
      continue;
    }
    const bool timed_out = co_await runtime::ReadyAwaitable{fd, POLLOUT, deadline};
    if (timed_out) {
      ::close(fd);
      ::freeaddrinfo(list);
      ProxyError error;
      error.kind = ProxyError::Kind::Timeout;
      co_return Result::fail(error);
    }
    int sock_error = 0;
    socklen_t len = sizeof(sock_error);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_error, &len) == 0 &&
        sock_error == 0) {
      ::freeaddrinfo(list);
      co_return Result::ok(fd);
    }
    if (sock_error != 0) {
      last_error = sock_error;
    }
    ::close(fd);
  }
  ::freeaddrinfo(list);
  co_return Result::fail(
      RequestFailed(std::string("connect failed: ") + std::strerror(last_error)));
}

/**
 * @brief Fetches one URL once (no redirects).
 * @return Status + (body on success, location on redirect).
 */
void CloseFetchFd(int fd, const std::shared_ptr<TlsChannel>& channel) {
  if (!channel) {
    ::close(fd);
  }
}

runtime::Task<runtime::Expected<FetchResult, ProxyError>> FetchOnce(
    const UrlParts& parts, std::size_t max_bytes, runtime::TimePoint deadline) {
  using Result = runtime::Expected<FetchResult, ProxyError>;
  auto connected = co_await Connect(parts, deadline);
  if (!connected.has_value()) {
    co_return Result::fail(connected.error());
  }
  const int fd = connected.value();
  std::shared_ptr<TlsChannel> channel;
  if (parts.scheme == "https") {
    auto opened = co_await OpenTlsChannel(fd, parts, deadline);
    if (!opened.has_value()) {
      CloseFetchFd(fd, channel);
      co_return Result::fail(opened.error());
    }
    channel = opened.value();
  }
  const std::string port =
      parts.port_str.empty() ? DefaultPort(parts.scheme) : parts.port_str;
  const std::string host_header = (port == DefaultPort(parts.scheme))
                                      ? parts.host
                                      : parts.host + ":" + port;
  std::string request = "GET " + parts.target + " HTTP/1.1\r\n";
  request += "Host: " + host_header + "\r\n";
  request += "Accept-Encoding: identity\r\n";
  request += "Connection: close\r\n\r\n";
  if (channel != nullptr) {
    std::size_t sent_total = 0;
    while (sent_total < request.size()) {
      const int n = SSL_write(channel->ssl, request.data() + sent_total,
                             static_cast<int>(request.size() - sent_total));
      if (n > 0) {
        sent_total += static_cast<std::size_t>(n);
        continue;
      }
      const int err = SSL_get_error(channel->ssl, n);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        const bool timed_out = co_await runtime::ReadyAwaitable{
            fd, static_cast<short>(err == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), deadline};
        if (timed_out) {
          ProxyError error;
          error.kind = ProxyError::Kind::Timeout;
          co_return Result::fail(error);
        }
        continue;
      }
      co_return Result::fail(RequestFailed("TLS write failed"));
    }
  } else {
    auto sent =
        co_await runtime::write_all(fd, request.data(), request.size(), deadline);
    if (!sent.has_value()) {
      CloseFetchFd(fd, channel);
      if (sent.error().timed_out) {
        ProxyError error;
        error.kind = ProxyError::Kind::Timeout;
        co_return Result::fail(error);
      }
      co_return Result::fail(RequestFailed(std::strerror(sent.error().err)));
    }
  }
  FetchReader reader{fd, deadline, "", channel};
  auto header_end = co_await reader.find_headers();
  if (!header_end.has_value()) {
    CloseFetchFd(fd, channel);
    co_return Result::fail(header_end.error());
  }
  const std::string head = reader.buffer.substr(0, header_end.value());
  reader.buffer.erase(0, header_end.value() + 4);
  // Status line.
  const std::size_t line_end = head.find("\r\n");
  const std::string status_line = head.substr(0, line_end);
  const std::size_t sp1 = status_line.find(' ');
  const std::size_t sp2 =
      sp1 == std::string::npos ? std::string::npos : status_line.find(' ', sp1 + 1);
  if (sp1 == std::string::npos) {
    CloseFetchFd(fd, channel);
    co_return Result::fail(RequestFailed("malformed upstream status line"));
  }
  const std::string code_text = status_line.substr(
      sp1 + 1, sp2 == std::string::npos ? sp2 : sp2 - sp1 - 1);
  int status = 0;
  try {
    status = std::stoi(code_text);
  } catch (...) {
    CloseFetchFd(fd, channel);
    co_return Result::fail(RequestFailed("malformed upstream status line"));
  }
  FetchResult result;
  result.status = status;
  // Headers: Location, Content-Length, chunked detection.
  std::optional<std::uint64_t> content_length;
  bool chunked = false;
  std::size_t at = line_end + 2;
  while (at < head.size()) {
    const std::size_t next = head.find("\r\n", at);
    const std::string line = head.substr(
        at, next == std::string::npos ? next : next - at);
    const std::size_t colon = line.find(':');
    if (colon != std::string::npos) {
      const std::string name = ToLower(line.substr(0, colon));
      std::string value = line.substr(colon + 1);
      const std::size_t first = value.find_first_not_of(" \t");
      value = first == std::string::npos ? std::string() : value.substr(first);
      const std::size_t last = value.find_last_not_of(" \t");
      value = last == std::string::npos ? std::string() : value.substr(0, last + 1);
      if (name == "location") {
        result.location = value;
      } else if (name == "content-length") {
        // Hyper rejects conflicting duplicates; the first value governs here.
        if (!content_length.has_value()) {
          const bool digits = !value.empty() &&
              value.find_first_not_of("0123456789") == std::string::npos;
          if (digits) {
            try {
              content_length = std::stoull(value);
            } catch (...) {
              CloseFetchFd(fd, channel);
              co_return Result::fail(
                  RequestFailed("invalid Content-Length header"));
            }
          }
        }
      } else if (name == "transfer-encoding" &&
                 ToLower(value).find("chunked") != std::string::npos) {
        chunked = true;
      }
    }
    if (next == std::string::npos) {
      break;
    }
    at = next + 2;
  }
  if (status < 200 || status >= 300) {
    CloseFetchFd(fd, channel);
    co_return Result::ok(result);
  }
  // Read the body, enforcing max_bytes incrementally.
  std::vector<std::uint8_t> body;
  auto feed = [&body, max_bytes](const char* data, std::size_t count) {
    if (body.size() + count > max_bytes) {
      return false;
    }
    body.insert(body.end(), data, data + count);
    return true;
  };
  if (chunked) {
    for (;;) {
      auto size_line = co_await reader.read_line();
      if (!size_line.has_value()) {
        CloseFetchFd(fd, channel);
        co_return Result::fail(size_line.error());
      }
      const std::string& raw = size_line.value();
      const std::size_t semi = raw.find(';');
      const std::string hex = raw.substr(0, semi);
      std::uint64_t chunk_size = 0;
      if (hex.empty() || hex.find_first_not_of("0123456789abcdefABCDEF") !=
                             std::string::npos) {
        CloseFetchFd(fd, channel);
        co_return Result::fail(RequestFailed("malformed chunked encoding"));
      }
      for (char c : hex) {
        chunk_size *= 16;
        const char lower = (c >= 'A' && c <= 'F') ? static_cast<char>(c + ('a' - 'A'))
                                                   : c;
        chunk_size += (lower <= '9')
                          ? static_cast<std::uint64_t>(lower - '0')
                          : static_cast<std::uint64_t>(lower - 'a' + 10);
      }
      if (chunk_size == 0) {
        // Consume trailers until an empty line.
        for (;;) {
          auto trailer = co_await reader.read_line();
          if (!trailer.has_value()) {
            CloseFetchFd(fd, channel);
            co_return Result::fail(trailer.error());
          }
          if (trailer.value().empty()) {
            break;
          }
        }
        break;
      }
      std::uint64_t remaining = chunk_size;
      while (remaining > 0) {
        const std::size_t wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, 4096));
        if (reader.buffer.size() < wanted) {
          auto more = co_await reader.fill();
          if (!more.has_value()) {
            CloseFetchFd(fd, channel);
            co_return Result::fail(more.error());
          }
          if (!more.value()) {
            CloseFetchFd(fd, channel);
            co_return Result::fail(RequestFailed(
                "connection closed before response body completed"));
          }
          continue;
        }
        if (!feed(reader.buffer.data(), wanted)) {
          CloseFetchFd(fd, channel);
          ProxyError error;
          error.kind = ProxyError::Kind::Oversize;
          co_return Result::fail(error);
        }
        reader.buffer.erase(0, wanted);
        remaining -= wanted;
      }
      // Trailing CRLF after chunk data.
      // Consume the two bytes (they may span fills).
      while (reader.buffer.size() < 2) {
        auto more = co_await reader.fill();
        if (!more.has_value()) {
          CloseFetchFd(fd, channel);
          co_return Result::fail(more.error());
        }
        if (!more.value()) {
          CloseFetchFd(fd, channel);
          co_return Result::fail(RequestFailed(
              "connection closed before response body completed"));
        }
      }
      reader.buffer.erase(0, 2);
    }
  } else if (content_length.has_value()) {
    std::uint64_t remaining = *content_length;
    while (remaining > 0) {
      const std::size_t wanted = static_cast<std::size_t>(
          std::min<std::uint64_t>(remaining, 4096));
      if (reader.buffer.empty()) {
        auto more = co_await reader.fill();
        if (!more.has_value()) {
          CloseFetchFd(fd, channel);
          co_return Result::fail(more.error());
        }
        if (!more.value()) {
          CloseFetchFd(fd, channel);
          co_return Result::fail(RequestFailed(
              "connection closed before response body completed"));
        }
        continue;
      }
      const std::size_t take = std::min(wanted, reader.buffer.size());
      if (!feed(reader.buffer.data(), take)) {
        CloseFetchFd(fd, channel);
        ProxyError error;
        error.kind = ProxyError::Kind::Oversize;
        co_return Result::fail(error);
      }
      reader.buffer.erase(0, take);
      remaining -= take;
    }
  } else {
    for (;;) {
      if (!reader.buffer.empty()) {
        if (!feed(reader.buffer.data(), reader.buffer.size())) {
          CloseFetchFd(fd, channel);
          ProxyError error;
          error.kind = ProxyError::Kind::Oversize;
          co_return Result::fail(error);
        }
        reader.buffer.clear();
      }
      auto more = co_await reader.fill();
      if (!more.has_value()) {
        CloseFetchFd(fd, channel);
        co_return Result::fail(more.error());
      }
      if (!more.value()) {
        break;
      }
    }
  }
  result.body = std::move(body);
  CloseFetchFd(fd, channel);
  co_return Result::ok(result);
}

class ProxyPlugin final : public PluginHandler {
 public:
  explicit ProxyPlugin(ProxyConfig config) : config_(std::move(config)) {}

  std::string route() const override { return config_.route; }

  runtime::Task<HttpResponse> dispatch(const PluginRequest& /*request*/,
                                       TtlCache& cache) override {
    if (config_.cache_seconds > 0) {
      if (auto fresh = cache.fresh(config_.route)) {
        co_return ProxyResponse(config_, *fresh);
      }
    }
    auto deadline = runtime::Clock::now() +
                    std::chrono::seconds(config_.timeout_seconds);
    auto fetched = co_await fetch(config_.url, config_.redirect_hosts,
                                  config_.max_bytes, deadline);
    if (fetched.has_value()) {
      if (config_.cache_seconds > 0) {
        cache.put(config_.route, fetched.value(),
                  std::chrono::seconds(config_.cache_seconds));
      }
      co_return ProxyResponse(config_, fetched.value());
    }
    if (auto stale = cache.stale(config_.route)) {
      co_return ProxyResponse(config_, *stale);
    }
    if (fetched.error().kind == ProxyError::Kind::Timeout) {
      co_return ErrorResponse("HTTP/1.1 504 Gateway Timeout\r\n",
                              fetched.error().message());
    }
    co_return ErrorResponse("HTTP/1.1 502 Bad Gateway\r\n",
                            fetched.error().message());
  }

 private:
  static HttpResponse ProxyResponse(const ProxyConfig& config,
                                    const std::vector<std::uint8_t>& body) {
    HttpResponse response;
    response.status = "HTTP/1.1 200 OK\r\n";
    std::string headers = "Content-Length: " + std::to_string(body.size()) +
                          "\r\nContent-Type: " + config.content_type + "\r\n";
    if (config.content_disposition.has_value()) {
      headers += "Content-Disposition: " + *config.content_disposition + "\r\n";
    }
    headers += "\r\n";
    response.headers = std::move(headers);
    response.body = body;
    return response;
  }

  static HttpResponse ErrorResponse(const std::string& status,
                                    const std::string& message) {
    const std::string body = "<h1>" + message + "</h1>";
    HttpResponse response;
    response.status = status;
    response.headers = "Content-Length: " + std::to_string(body.size()) +
                       "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
    response.body.assign(body.begin(), body.end());
    return response;
  }

  ProxyConfig config_;
};

}  // namespace

std::string ProxyError::message() const {
  switch (kind) {
    case Kind::Timeout:
      return "upstream request timed out";
    case Kind::Oversize:
      return "upstream response exceeded max_bytes";
    case Kind::Request:
      return "upstream request failed: " + detail;
    case Kind::Status:
      return "upstream returned HTTP " + std::to_string(status_code) + " " +
             status_text;
  }
  return "upstream request failed";
}

runtime::Task<runtime::Expected<std::vector<std::uint8_t>, ProxyError>> fetch(
    const std::string& url, const std::vector<std::string>& redirect_hosts,
    std::size_t max_bytes, runtime::TimePoint deadline) {
  using Result = runtime::Expected<std::vector<std::uint8_t>, ProxyError>;
  auto parts = ParseUrl(url);
  if (!parts.has_value()) {
    co_return Result::fail(RequestFailed("invalid upstream URL"));
  }
  UrlParts current = *parts;
  int previous = 0;
  for (;;) {
    auto outcome = co_await FetchOnce(current, max_bytes, deadline);
    if (!outcome.has_value()) {
      co_return Result::fail(outcome.error());
    }
    FetchResult& result = outcome.value();
    if (result.status >= 200 && result.status < 300) {
      co_return Result::ok(std::move(result.body));
    }
    if (result.status >= 300 && result.status < 400 &&
        !result.location.empty() && previous < 10) {
      // Resolve the next URL (absolute, or absolute-path).
      std::string next_url = result.location;
      std::optional<UrlParts> next_parts;
      if (next_url.find("://") != std::string::npos) {
        next_parts = ParseUrl(next_url);
      } else {
        std::string joined;
        if (!next_url.empty() && next_url.front() == '/') {
          joined = next_url;
        } else {
          joined = "/" + next_url;
        }
        const std::string port =
            current.port_str.empty() ? DefaultPort(current.scheme)
                                     : ":" + current.port_str;
        next_url = current.scheme + "://" + current.host + port + joined;
        next_parts = ParseUrl(next_url);
      }
      if (!next_parts.has_value()) {
        co_return Result::fail(StatusFailed(result.status));
      }
      bool allowed = false;
      for (const auto& host : redirect_hosts) {
        if (EqIgnoreCase(host, next_parts->host)) {
          allowed = true;
          break;
        }
      }
      if (!allowed) {
        co_return Result::fail(StatusFailed(result.status));
      }
      current = *next_parts;
      ++previous;
      continue;
    }
    co_return Result::fail(StatusFailed(result.status));
  }
}

std::shared_ptr<PluginHandler> ProxyFactory::build(
    const std::string& /*instance*/,
    const std::map<std::string, std::string>& fields) {
  static const std::set<std::string> kAllowed = {
      "route",          "url",                "content_type",
      "content_disposition", "redirect_hosts", "cache_seconds",
      "timeout_seconds", "max_bytes"};
  for (const auto& [field, value] : fields) {
    (void)value;
    if (!kAllowed.contains(field)) {
      throw ConfigError("unknown proxy field: " + field);
    }
  }
  const auto required = [&fields](const std::string& name) -> std::string {
    const auto it = fields.find(name);
    if (it == fields.end() || it->second.empty()) {
      throw ConfigError("missing proxy field: " + name);
    }
    return it->second;
  };
  ProxyConfig config;
  config.route = required("route");
  validate_route_path(config.route);
  config.url = required("url");
  const std::size_t scheme_end = config.url.find("://");
  if (scheme_end == std::string::npos) {
    throw ConfigError("proxy url must be a valid URL");
  }
  const std::string scheme = ToLower(config.url.substr(0, scheme_end));
  if (scheme != "http" && scheme != "https") {
    throw ConfigError("proxy url must use http or https");
  }
  {
    const std::string rest = config.url.substr(scheme_end + 3);
    const std::string authority =
        rest.substr(0, rest.find_first_of("/?#"));
    if (authority.empty() || authority.find('@') != std::string::npos) {
      throw ConfigError("proxy url must contain a host and no userinfo");
    }
  }
  auto parts = ParseUrl(config.url);
  if (!parts.has_value()) {
    throw ConfigError("proxy url must be a valid URL");
  }
  config.content_type = required("content_type");
  validate_header_value(config.content_type);
  if (const auto it = fields.find("content_disposition");
      it != fields.end() && !it->second.empty()) {
    validate_header_value(it->second);
    config.content_disposition = it->second;
  }
  config.redirect_hosts = ParseRedirectHosts(fields, parts->host);
  config.cache_seconds = ParseInteger(fields, "cache_seconds", true);
  config.timeout_seconds = ParseInteger(fields, "timeout_seconds", false);
  const std::uint64_t max_bytes = ParseInteger(fields, "max_bytes", false);
  if (max_bytes >
      static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    throw ConfigError("max_bytes is too large");
  }
  config.max_bytes = static_cast<std::size_t>(max_bytes);
  return std::make_shared<ProxyPlugin>(std::move(config));
}

}  // namespace ronfire::proxy
