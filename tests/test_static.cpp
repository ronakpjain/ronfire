/** @file test_static.cpp @brief Static file tests. */

#include "test_util.h"

using namespace testutil;

void WriteFile(const std::filesystem::path& path, const std::string& text) {
  std::ofstream out(path);
  out << text;
}

TEST(Static, DocumentRootContainment) {
  namespace fs = std::filesystem;
  const fs::path base = fs::temp_directory_path() /
                        ("ronfire-test-" + std::to_string(::getpid()));
  const fs::path root = base / "root";
  std::error_code ec;
  fs::remove_all(base, ec);
  fs::create_directories(root / "sub");
  fs::create_directories(root / ".git");
  WriteFile(root / "index.html", "<h1>root</h1>");
  WriteFile(root / "page.html", "<h1>page</h1>");
  WriteFile(root / "sub" / "index.html", "<h1>sub</h1>");
  WriteFile(root / "app.log", "secret");
  WriteFile(root / ".git" / "config", "secret");
  WriteFile(root / "denied.txt", "denied");
  WriteFile(base / "outside.txt", "outside");
  fs::create_symlink(base / "outside.txt", root / "link.txt");

  const auto docroot = ronfire::DocumentRoot::make(
      root.string(), (root / "denied.txt").string());
  ASSERT_TRUE(docroot.has_value()) << docroot.error();
  const auto& root_ref = docroot.value();
  EXPECT_TRUE(root_ref.resolve("/").has_value());
  EXPECT_TRUE(root_ref.resolve("/page").has_value());
  EXPECT_TRUE(root_ref.resolve("/sub/").has_value());
  EXPECT_FALSE(root_ref.resolve("/app.log").has_value());
  EXPECT_FALSE(root_ref.resolve("/.git/config").has_value());
  EXPECT_FALSE(root_ref.resolve("/../outside.txt").has_value());
  EXPECT_FALSE(root_ref.resolve("/denied.txt").has_value());
  EXPECT_FALSE(root_ref.resolve("/link.txt").has_value());
  EXPECT_FALSE(root_ref.resolve("/missing.html").has_value());
  const auto page = root_ref.resolve("/page");
  ASSERT_TRUE(page.has_value());
  const auto response = ronfire::generate_response(*page);
  EXPECT_EQ(response.status, "HTTP/1.1 200 OK\r\n");
  EXPECT_NE(response.headers.find("Content-Type: text/html"),
            std::string::npos);
  EXPECT_EQ(ronfire::guess_mime_type("/x/Resume.pdf"), "application/pdf");
  fs::remove_all(base, ec);
}

