cmake_minimum_required(VERSION 3.20)

project(ronfire VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# POSIX interfaces used by the hand-written runtime (poll, sockets, realpath).
add_compile_definitions(_POSIX_C_SOURCE=200809L _DEFAULT_SOURCE)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(ronfire_lib STATIC
  src/cli.cpp
  src/http.cpp
  src/runtime/loop.cpp
  src/runtime/io.cpp
  src/transport.cpp
)
target_include_directories(ronfire_lib PUBLIC src)

add_executable(ronfire src/main.cpp)
target_link_libraries(ronfire PRIVATE ronfire_lib)

enable_testing()
find_package(GTest REQUIRED)
add_executable(ronfire_tests tests/test_main.cpp)
target_link_libraries(ronfire_tests PRIVATE ronfire_lib GTest::gtest GTest::gtest_main)
add_test(NAME ronfire_tests COMMAND ronfire_tests)
