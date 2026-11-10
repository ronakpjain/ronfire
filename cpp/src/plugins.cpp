/** @file plugins.cpp @brief Plugin registry implementation (see plugins.h). */

#include "plugins.h"

#include <fstream>
#include <map>
#include <set>
#include <utility>

#include "plugins/proxy.h"

namespace ronfire {
namespace {

bool ValidIdentifier(const std::string& value) {
  if (value.empty()) {
    return false;
  }
  for (char c : value) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') || c == '_' || c == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

std::string TrimAscii(std::string s) {
  std::size_t start = 0;
  while (start < s.size() && (s[start] == ' ' || s[start] == '\t' ||
                              s[start] == '\r')) {
    ++start;
  }
  std::size_t end = s.size();
  while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' ||
                         s[end - 1] == '\r')) {
    --end;
  }
  return s.substr(start, end - start);
}

[[noreturn]] void ThrowLine(std::size_t line, const std::string& message) {
  throw ConfigError("line " + std::to_string(line) + ": " + message);
}

struct RawSection {
  std::string plugin;
  std::string instance;
  std::size_t line;
  std::map<std::string, std::string> fields;
};

}  // namespace

// --- cache -------------------------------------------------------------------

std::optional<std::vector<std::uint8_t>> TtlCache::fresh(
    const std::string& key) const {
  const auto it = entries_.find(key);
  if (it == entries_.end() || runtime::Clock::now() >= it->second.expires_at) {
    return std::nullopt;
  }
  return it->second.body;
}

std::optional<std::vector<std::uint8_t>> TtlCache::stale(
    const std::string& key) const {
  const auto it = entries_.find(key);
  if (it == entries_.end()) {
    return std::nullopt;
  }
  return it->second.body;
}

void TtlCache::put(std::string key, std::vector<std::uint8_t> body,
                   std::chrono::seconds ttl) {
  entries_[std::move(key)] =
      Entry{std::move(body), runtime::Clock::now() + ttl};
}

// --- registry ----------------------------------------------------------------

void PluginRegistry::register_plugin(
    std::string name, std::shared_ptr<PluginFactory> factory) {
  if (!ValidIdentifier(name)) {
    throw ConfigError("invalid plugin name \"" + name + "\"");
  }
  if (!factories_.emplace(name, std::move(factory)).second) {
    throw ConfigError("duplicate plugin registration: " + name);
  }
}

std::optional<std::shared_ptr<PluginFactory>> PluginRegistry::factory(
    const std::string& name) const {
  const auto it = factories_.find(name);
  if (it == factories_.end()) {
    return std::nullopt;
  }
  return it->second;
}

PluginRegistry PluginRegistry::with_builtins() {
  PluginRegistry registry;
  registry.register_plugin("proxy", std::make_shared<proxy::ProxyFactory>());
  return registry;
}

// --- validators --------------------------------------------------------------

void validate_route_path(const std::string& path) {
  if (path.empty() || path.front() != '/') {
    throw ConfigError("route must start with /");
  }
  if (path.find_first_of("?#\\\0") != std::string::npos) {
    throw ConfigError("route contains an invalid character or traversal component");
  }
  std::size_t at = 0;
  while (at <= path.size()) {
    const std::size_t slash = path.find('/', at);
    const std::string part =
        path.substr(at, slash == std::string::npos ? slash : slash - at);
    if (part == "..") {
      throw ConfigError(
          "route contains an invalid character or traversal component");
    }
    for (char c : part) {
      const auto byte = static_cast<unsigned char>(c);
      if (byte <= 0x20 || byte == 0x7f) {
        throw ConfigError(
            "route contains an invalid character or traversal component");
      }
    }
    if (slash == std::string::npos) {
      break;
    }
    at = slash + 1;
  }
}

void validate_header_value(const std::string& value) {
  for (char c : value) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte < 0x20 || byte == 0x7f) {
      throw ConfigError("response header values must not contain control characters");
    }
  }
}

// --- config parsing ----------------------------------------------------------

RouteConfig RouteConfig::parse(const std::string& contents) {
  return parse_with_registry(contents, PluginRegistry::with_builtins());
}

RouteConfig RouteConfig::parse_with_registry(
    const std::string& contents, const PluginRegistry& registry) {
  std::vector<RawSection> sections;
  std::optional<RawSection> current;
  std::size_t line_number = 0;
  std::size_t at = 0;
  while (at <= contents.size()) {
    const std::size_t newline = contents.find('\n', at);
    ++line_number;
    std::string raw = contents.substr(
        at, newline == std::string::npos ? newline : newline - at);
    at = newline == std::string::npos ? contents.size() + 1 : newline + 1;
    if (!raw.empty() && raw.back() == '\r') {
      raw.pop_back();
    }
    const std::string trimmed = TrimAscii(raw);
    if (trimmed.empty() || trimmed.front() == '#' || trimmed.front() == ';') {
      continue;
    }
    if (trimmed.front() == '[') {
      if (trimmed.size() < 2 || trimmed.back() != ']') {
        ThrowLine(line_number, "malformed section header");
      }
      if (current.has_value()) {
        sections.push_back(std::move(*current));
        current.reset();
      }
      const std::string section = trimmed.substr(1, trimmed.size() - 2);
      constexpr std::string_view kPrefix = "plugin.";
      if (section.rfind(kPrefix, 0) != 0) {
        ThrowLine(line_number, "section must use [plugin.NAME.INSTANCE]");
      }
      const std::string rest = section.substr(kPrefix.size());
      std::vector<std::string> names;
      std::size_t p = 0;
      for (;;) {
        const std::size_t dot = rest.find('.', p);
        names.push_back(rest.substr(
            p, dot == std::string::npos ? dot : dot - p));
        if (dot == std::string::npos) {
          break;
        }
        p = dot + 1;
      }
      if (names.size() != 2 || names[0].empty() || names[1].empty()) {
        if (names.size() < 2 || names[0].empty()) {
          ThrowLine(line_number, "missing plugin name");
        }
        if (names.size() < 2 || names[1].empty()) {
          ThrowLine(line_number, "missing plugin instance");
        }
        ThrowLine(line_number,
                  "plugin and instance names must be simple identifiers");
      }
      if (!ValidIdentifier(names[0]) || !ValidIdentifier(names[1])) {
        ThrowLine(line_number,
                  "plugin and instance names must be simple identifiers");
      }
      current = RawSection{names[0], names[1], line_number, {}};
      continue;
    }
    if (!current.has_value()) {
      ThrowLine(line_number, "key/value appears before a plugin section");
    }
    const std::size_t equals = raw.find('=');
    if (equals == std::string::npos) {
      ThrowLine(line_number, "expected key = value");
    }
    const std::string key = TrimAscii(raw.substr(0, equals));
    const std::string value = TrimAscii(raw.substr(equals + 1));
    if (!ValidIdentifier(key)) {
      ThrowLine(line_number, "malformed field name");
    }
    if (current->fields.contains(key)) {
      ThrowLine(line_number, "duplicate field: " + key);
    }
    current->fields[key] = value;
  }
  if (current.has_value()) {
    sections.push_back(std::move(*current));
  }

  RouteConfig result;
  std::set<std::pair<std::string, std::string>> instances;
  for (auto& section : sections) {
    if (!instances.insert({section.plugin, section.instance}).second) {
      ThrowLine(section.line, "duplicate plugin instance");
    }
    auto factory = registry.factory(section.plugin);
    if (!factory.has_value()) {
      ThrowLine(section.line, "unknown plugin: " + section.plugin);
    }
    std::shared_ptr<PluginHandler> handler;
    try {
      handler = (*factory)->build(section.instance, section.fields);
    } catch (const ConfigError& error) {
      ThrowLine(section.line, error.what());
    }
    const std::string path = handler->route();
    for (const auto& route : result.routes_) {
      if (route.path == path) {
        ThrowLine(section.line, "duplicate route: " + path);
      }
    }
    result.routes_.push_back(RegisteredRoute{path, std::move(handler)});
  }
  return result;
}

RouteConfig RouteConfig::load(const std::string& path,
                              const PluginRegistry& registry,
                              bool missing_allowed) {
  std::ifstream file(path);
  if (!file) {
    if (missing_allowed) {
      return RouteConfig{};
    }
    throw ConfigError("cannot read config " + path + ": cannot open file");
  }
  const std::string contents((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
  return parse_with_registry(contents, registry);
}

std::optional<std::shared_ptr<PluginHandler>> RouteConfig::route_for(
    const std::string& path) const {
  for (const auto& route : routes_) {
    if (route.path == path) {
      return route.handler;
    }
  }
  return std::nullopt;
}

runtime::Task<std::optional<HttpResponse>> dispatch_request(RouteConfig& routes,
                                                            const HttpRequest& request,
                                                            TtlCache& cache) {
  auto handler = routes.route_for(request.path);
  if (!handler.has_value()) {
    co_return std::nullopt;
  }
  PluginRequest plugin_request;
  plugin_request.method = request.method;
  plugin_request.target = request.target;
  plugin_request.path = request.path;
  plugin_request.headers = request.headers;
  plugin_request.range = request.range;
  HttpResponse response = co_await (*handler)->dispatch(plugin_request, cache);
  co_return std::optional<HttpResponse>(finalize_response(std::move(response), request));
}

}  // namespace ronfire
