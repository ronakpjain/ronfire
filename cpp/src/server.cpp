/** @file server.cpp @brief Server implementation (see server.h). */

#include "server.h"

#include <unistd.h>

#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "cli.h"
#include "http.h"
#include "static_files.h"
#include "transport.h"

namespace ronfire {
namespace {

/**
 * @brief Applies Connection persistence to a response header block.
 * @param response Response to mutate.
 * @param keep_alive Whether the connection stays open.
 */
void PrependConnection(HttpResponse& response, bool keep_alive) {
  response.headers = std::string(keep_alive ? "Connection: keep-alive\r\n"
                                            : "Connection: close\r\n") +
                     response.headers;
}

/**
 * @brief Wraps an error into a startup exception.
 * @param message Startup error text.
 * @return Runtime error with the message.
 */
std::runtime_error StartupError(const std::string& message) {
  return std::runtime_error(message);
}

/**
 * @brief Sends a simple closing error response (Connection: close).
 * @param fd Connection fd.
 * @param status Status line, e.g. "HTTP/1.1 400 Bad Request\r\n".
 * @param body Body text.
 */
runtime::Task<void> SendSimple(int fd, const std::string& status,
                                const std::string& body) {
  HttpResponse response;
  response.status = status;
  response.headers = "Connection: close\r\nContent-Length: " +
                     std::to_string(body.size()) +
                     "\r\nContent-Type: text/html\r\n\r\n";
  response.body.assign(body.begin(), body.end());
  co_await send_response(fd, response, nullptr);
  co_return;
}

/**
 * @brief Builds the response for one parsed request (before Connection).
 * @param request Parsed request.
 * @param document_root Secure document root.
 */
HttpResponse HandleRequest(const HttpRequest& request,
                           const DocumentRoot& document_root) {
  if (request.method != "GET" && request.method != "HEAD") {
    HttpResponse response;
    response.status = "HTTP/1.1 405 Method Not Allowed\r\n";
    response.headers = "Allow: GET, HEAD\r\nContent-Length: 0\r\n\r\n";
    return response;
  }
  if (auto full_path = document_root.resolve(request.path)) {
    return finalize_response(generate_response(*full_path), request);
  }
  const std::string body = "<h1>404 Not Found</h1>";
  HttpResponse response;
  response.status = "HTTP/1.1 404 Not Found\r\n";
  response.headers = "Content-Length: " + std::to_string(body.size()) +
                     "\r\nContent-Type: text/html\r\n\r\n";
  response.body.assign(body.begin(), body.end());
  return finalize_response(std::move(response), request);
}

/**
 * @brief Serves one connection until close or error.
 * @param fd Connection fd (closed by this task on exit).
 * @param document_root Shared document root.
 * @param logger Shared logger.
 */
runtime::Task<void> HandleConnection(int fd, const DocumentRoot& document_root,
                                     const AsyncLogger& logger) {
  BufferedReader reader(fd);
  for (;;) {
    auto deadline = runtime::Clock::now() + kRequestIdleTimeout;
    auto request = co_await reader.read_next(deadline);
    if (!request.has_value()) {
      switch (request.error().kind) {
        case RequestReadError::Kind::HeaderTooLarge: {
          co_await SendSimple(fd,
                              "HTTP/1.1 431 Request Header Fields Too Large\r\n",
                              "<h1>431 Request Header Fields Too Large</h1>");
          break;
        }
        case RequestReadError::Kind::Malformed: {
          logger.log("Malformed request: " + request.error().message);
          co_await SendSimple(fd, "HTTP/1.1 400 Bad Request\r\n",
                              "<h1>400 Bad Request</h1>");
          break;
        }
        case RequestReadError::Kind::Io: {
          logger.log("Request read failed: " +
                     std::string(std::strerror(request.error().io.err)));
          break;
        }
        case RequestReadError::Kind::TimedOut: {
          co_await SendSimple(fd, "HTTP/1.1 408 Request Timeout\r\n",
                              "<h1>408 Request Timeout</h1>");
          break;
        }
      }
      break;
    }
    if (!request.value().has_value()) {
      break;
    }
    const HttpRequest parsed = *request.value();
    const bool keep_alive = parsed.keep_alive();
    HttpResponse response = HandleRequest(parsed, document_root);
    PrependConnection(response, keep_alive);
    co_await send_response(fd, response, &logger);
    if (!keep_alive) {
      break;
    }
  }
  ::close(fd);
  co_return;
}

}  // namespace

runtime::Task<void> run(std::vector<std::string> args) {
  auto parsed = parse_args(args);
  if (!parsed.has_value()) {
    throw StartupError(parsed.error());
  }
  const Args options = parsed.value();
  // Route loading lands with the plugin registry; today there are no routes.
  // Canonicalized config path denies itself from the document root.
  auto document_root = DocumentRoot::make(options.root_path, options.config_path);
  if (!document_root.has_value()) {
    throw StartupError(document_root.error());
  }
  const AsyncLogger logger;
  auto listener = create_socket(options.socket_path);
  if (!listener.has_value()) {
    throw StartupError("could not create ronfire Unix socket: " +
                       std::string(std::strerror(listener.error().err)));
  }
  for (;;) {
    auto accepted = co_await accept_once(listener.value(), std::nullopt);
    if (!accepted.has_value()) {
      if (accepted.error().timed_out) {
        throw StartupError("accept timed out");
      }
      throw StartupError(std::strerror(accepted.error().err));
    }
    runtime::EventLoop::current()->spawn(
        HandleConnection(accepted.value(), document_root.value(), logger));
  }
  co_return;
}

}  // namespace ronfire
