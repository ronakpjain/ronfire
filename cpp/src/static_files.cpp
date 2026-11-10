/** @file static_files.cpp @brief Static files implementation (see static_files.h). */

#include "static_files.h"

#include <sys/stat.h>

#include <cstdlib>
#include <fstream>
#include <utility>

#include "transport.h"

namespace ronfire {
namespace {

std::optional<std::string> Canonicalize(const std::string& path) {
  char buffer[PATH_MAX];
  if (::realpath(path.c_str(), buffer) == nullptr) {
    return std::nullopt;
  }
  return std::string(buffer);
}

bool StartsWith(const std::string& value, const std::string& prefix) {
  return value.size() >= prefix.size() &&
         value.compare(0, prefix.size(), prefix) == 0;
}

bool IsInsideRoot(const std::string& candidate, const std::string& root) {
  if (candidate == root) {
    return true;
  }
  if (!StartsWith(candidate, root)) {
    return false;
  }
  return root.back() == '/' || candidate[root.size()] == '/';
}

std::string Join(const std::string& root, const std::string& suffix) {
  if (root == "/") {
    return "/" + suffix;
  }
  return root + "/" + suffix;
}

bool IsRegularFile(const std::string& path) {
  struct stat info {};
  return ::stat(path.c_str(), &info) == 0 && S_ISREG(info.st_mode);
}

}  // namespace

std::optional<std::string> parse_request_path(const std::string& request,
                                              const AsyncLogger* logger) {
  auto parsed = parse_http_request(request);
  if (!parsed.has_value()) {
    return std::nullopt;
  }
  if (parsed.value().method != "GET" && parsed.value().method != "HEAD") {
    if (logger != nullptr) {
      logger->log("Unsupported HTTP Method: " + parsed.value().method);
    }
    return std::nullopt;
  }
  return parsed.value().path;
}

std::optional<std::string> parse_request(const std::string& request,
                                         const AsyncLogger* logger) {
  auto path = parse_request_path(request, logger);
  if (!path.has_value()) {
    return std::nullopt;
  }
  auto root = DocumentRoot::make(".", std::nullopt);
  if (!root.has_value()) {
    return std::nullopt;
  }
  return root.value().resolve(*path);
}

runtime::Expected<DocumentRoot, std::string> DocumentRoot::make(
    const std::string& root, const std::optional<std::string>& denied) {
  using Result = runtime::Expected<DocumentRoot, std::string>;
  auto canonical = Canonicalize(root);
  struct stat info {};
  if (!canonical.has_value() ||
      ::stat(canonical->c_str(), &info) != 0 || !S_ISDIR(info.st_mode)) {
    return Result::fail("document root is not a directory");
  }
  DocumentRoot result;
  result.canonical_root_ = *canonical;
  if (denied.has_value()) {
    result.denied_ = Canonicalize(*denied);
  }
  return Result::ok(std::move(result));
}

std::optional<std::string> DocumentRoot::resolve(const std::string& path) const {
  std::size_t first = 0;
  while (first < path.size() && path[first] == '/') {
    ++first;
  }
  const std::string relative = path.substr(first);
  if (!relative.empty()) {
    if (relative.find("//") != std::string::npos) {
      return std::nullopt;
    }
    std::size_t at = 0;
    while (at <= relative.size()) {
      const std::size_t slash = relative.find('/', at);
      const std::string part = relative.substr(
          at, slash == std::string::npos ? slash : slash - at);
      if (!part.empty() && part.front() == '.') {
        return std::nullopt;
      }
      if (slash == std::string::npos) {
        break;
      }
      at = slash + 1;
    }
  }
  std::vector<std::string> candidates;
  const bool trailing_slash = !relative.empty() && relative.back() == '/';
  if (relative.empty()) {
    candidates.push_back(Join(canonical_root_, "index.html"));
  } else if (trailing_slash) {
    candidates.push_back(Join(canonical_root_, relative + "index.html"));
  } else {
    const std::size_t slash = relative.rfind('/');
    const std::string last = relative.substr(
        slash == std::string::npos ? 0 : slash + 1);
    const std::size_t dot = last.rfind('.');
    const bool has_extension = dot != std::string::npos && dot != 0;
    if (!has_extension) {
      candidates.push_back(Join(canonical_root_, relative + ".html"));
      candidates.push_back(Join(canonical_root_, relative + "/index.html"));
    } else {
      candidates.push_back(Join(canonical_root_, relative));
    }
  }
  for (const auto& candidate : candidates) {
    auto canonical = Canonicalize(candidate);
    if (!canonical.has_value()) {
      continue;
    }
    const std::size_t slash = canonical->rfind('/');
    const std::string name =
        slash == std::string::npos ? *canonical : canonical->substr(slash + 1);
    if (!IsInsideRoot(*canonical, canonical_root_) ||
        (denied_.has_value() && *canonical == *denied_) ||
        name == "app.log" || !IsRegularFile(*canonical)) {
      continue;
    }
    return canonical;
  }
  return std::nullopt;
}

HttpResponse generate_response(const std::string& full_path) {
  HttpResponse response;
  std::ifstream file(full_path, std::ios::binary);
  if (!file) {
    response.status = "HTTP/1.1 404 Not Found\r\n";
    const std::string body = "<h1>404 Not Found</h1>";
    response.headers = "Content-Length: " + std::to_string(body.size()) +
                       "\r\nContent-Type: text/html\r\n\r\n";
    response.body.assign(body.begin(), body.end());
    return response;
  }
  std::vector<std::uint8_t> contents((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());
  response.status = "HTTP/1.1 200 OK\r\n";
  response.headers = "Content-Length: " + std::to_string(contents.size()) +
                     "\r\nContent-Type: " + guess_mime_type(full_path) +
                     "\r\nAccept-Ranges: bytes\r\n\r\n";
  response.body = std::move(contents);
  return response;
}

std::string guess_mime_type(const std::string& path) {
  const std::size_t slash = path.rfind('/');
  const std::string last =
      slash == std::string::npos ? path : path.substr(slash + 1);
  const std::size_t dot = last.rfind('.');
  if (dot == std::string::npos) {
    return "application/octet-stream";
  }
  const std::string ext = last.substr(dot + 1);
  if (ext == "html" || ext == "htm") return "text/html";
  if (ext == "css") return "text/css";
  if (ext == "js") return "application/javascript";
  if (ext == "json") return "application/json";
  if (ext == "pdf") return "application/pdf";
  if (ext == "png") return "image/png";
  if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
  if (ext == "webp") return "image/webp";
  if (ext == "gif") return "image/gif";
  if (ext == "svg") return "image/svg+xml";
  if (ext == "ico") return "image/x-icon";
  if (ext == "txt") return "text/plain";
  if (ext == "wasm") return "application/wasm";
  if (ext == "woff") return "font/woff";
  if (ext == "woff2") return "font/woff2";
  if (ext == "ttf") return "font/ttf";
  if (ext == "otf") return "font/otf";
  if (ext == "mp4") return "video/mp4";
  if (ext == "webm") return "video/webm";
  if (ext == "ogg") return "audio/ogg";
  if (ext == "mp3") return "audio/mpeg";
  return "application/octet-stream";
}

}  // namespace ronfire
