cmake_minimum_required(VERSION 3.20)

project(ronfire VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# POSIX interfaces used by the hand-written runtime (poll, sockets, realpath).
add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(ronfire_lib STATIC
  src/cli.cpp
  src/http.cpp
  src/plugins.cpp
  src/plugins/proxy.cpp
  src/runtime/loop.cpp
  src/runtime/io.cpp
  src/server.cpp
  src/static_files.cpp
  src/transport.cpp
)
target_include_directories(ronfire_lib PUBLIC src)
target_link_libraries(ronfire_lib PUBLIC Threads::Threads OpenSSL::SSL OpenSSL::Crypto)

add_executable(ronfire src/main.cpp)
target_link_libraries(ronfire PRIVATE ronfire_lib)

enable_testing()
find_package(GTest QUIET)
if(GTest_FOUND)
  add_executable(ronfire_tests
    tests/test_runtime.cpp
    tests/test_cli.cpp
    tests/test_http.cpp
    tests/test_static.cpp
    tests/test_transport.cpp
    tests/test_plugins.cpp
    tests/test_proxy.cpp
    tests/test_util.h)
  target_link_libraries(ronfire_tests PRIVATE ronfire_lib GTest::gtest GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(ronfire_tests)
  add_test(NAME ronfire_smoke
           COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/smoke.sh
                   $<TARGET_FILE:ronfire>)
  set_tests_properties(ronfire_smoke PROPERTIES TIMEOUT 30)
else()
  message(STATUS "GTest not found; tests disabled.")
endif()
