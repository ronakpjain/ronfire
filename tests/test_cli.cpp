/** @file test_cli.cpp @brief CLI tests. */

#include "test_util.h"

using namespace testutil;

TEST(Cli, DefaultsAndFlags) {
  const auto defaults = parse_args({"ronfire"});
  ASSERT_TRUE(defaults.has_value());
  EXPECT_EQ(defaults.value().socket_path, "/tmp/ronfire.sock");
  EXPECT_EQ(defaults.value().config_path, "ronfire.conf");
  EXPECT_FALSE(defaults.value().config_explicit);
  EXPECT_EQ(defaults.value().root_path, ".");
  const auto full = parse_args(
      {"ronfire", "/tmp/a.sock", "--config=/x.conf", "--root", "/srv"});
  ASSERT_TRUE(full.has_value());
  EXPECT_EQ(full.value().socket_path, "/tmp/a.sock");
  EXPECT_EQ(full.value().config_path, "/x.conf");
  EXPECT_TRUE(full.value().config_explicit);
  EXPECT_EQ(full.value().root_path, "/srv");
}

TEST(Cli, Errors) {
  const auto unknown = parse_args({"ronfire", "--bogus"});
  ASSERT_FALSE(unknown.has_value());
  EXPECT_EQ(unknown.error(), "unknown option: --bogus");
  EXPECT_FALSE(parse_args({"ronfire", "--config"}).has_value());
  EXPECT_FALSE(parse_args({"ronfire", "--config="}).has_value());
  EXPECT_FALSE(parse_args({"ronfire", "/a", "/b"}).has_value());
}

