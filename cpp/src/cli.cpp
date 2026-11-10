/** @file cli.cpp @brief Implementation. */

// CLI parsing implementation. See cli.h for semantics.

#include "cli.h"

#include <utility>

namespace ronfire {

runtime::Expected<Args, std::string> parse_args(const std::vector<std::string>& args) {
  Args parsed;
  bool have_socket = false;
  for (std::size_t i = 1; i < args.size(); ++i) {
    const std::string& arg = args[i];
    auto take_next = [&](const char* flag) -> runtime::Expected<std::string, std::string> {
      if (i + 1 >= args.size()) {
        return runtime::Expected<std::string, std::string>::fail(
            std::string(flag) + " requires a path");
      }
      return runtime::Expected<std::string, std::string>::ok(args[++i]);
    };
    if (arg == "--config") {
      auto next = take_next("--config");
      if (!next.has_value()) {
        return runtime::Expected<Args, std::string>::fail(next.error());
      }
      parsed.config_path = next.value();
      parsed.config_explicit = true;
    } else if (arg.rfind("--config=", 0) == 0) {
      const std::string path = arg.substr(sizeof("--config=") - 1);
      if (path.empty()) {
        return runtime::Expected<Args, std::string>::fail("--config requires a path");
      }
      parsed.config_path = path;
      parsed.config_explicit = true;
    } else if (arg == "--root") {
      auto next = take_next("--root");
      if (!next.has_value()) {
        return runtime::Expected<Args, std::string>::fail(next.error());
      }
      parsed.root_path = next.value();
    } else if (arg.rfind("--root=", 0) == 0) {
      const std::string path = arg.substr(sizeof("--root=") - 1);
      if (path.empty()) {
        return runtime::Expected<Args, std::string>::fail("--root requires a path");
      }
      parsed.root_path = path;
    } else if (!arg.empty() && arg.front() == '-') {
      return runtime::Expected<Args, std::string>::fail("unknown option: " + arg);
    } else if (have_socket) {
      return runtime::Expected<Args, std::string>::fail("only one socket path may be specified");
    } else {
      parsed.socket_path = arg;
      have_socket = true;
    }
  }
  return runtime::Expected<Args, std::string>::ok(std::move(parsed));
}

}  // namespace ronfire
