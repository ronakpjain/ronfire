// Minimal test harness: no external test framework (dependency-free build).
// Each CHECK records a failure with source location; main exits non-zero if any
// check failed so ctest reports the suite.

#include <iostream>

namespace {

int g_checks = 0;
int g_failures = 0;

void Report(bool ok, const char* expr, const char* file, int line) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::cerr << file << ':' << line << ": CHECK(" << expr << ") failed\n";
  }
}

}  // namespace

#define CHECK(cond) Report(static_cast<bool>(cond), #cond, __FILE__, __LINE__)

int main() {
  CHECK(1 + 1 == 2);
  if (g_failures != 0) {
    std::cerr << g_failures << " of " << g_checks << " checks failed\n";
    return 1;
  }
  std::cout << "all " << g_checks << " checks passed\n";
  return 0;
}
