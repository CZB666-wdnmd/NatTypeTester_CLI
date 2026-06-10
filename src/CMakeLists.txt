cmake_minimum_required(VERSION 3.20)
project(NatTypeTesterCli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
include(CTest)

add_library(nat_type_tester_cli_lib
  utils/net_utils.cpp
  utils/stun_utils.cpp
  tests/test_dispatcher.cpp
  tests/rfc3489_test.cpp
  tests/rfc5780_test.cpp
  tests/rfc4787_test.cpp
  tests/rfc5382_test.cpp
  tests/rfc5508_test.cpp
  tests/rfc7857_test.cpp
)

target_include_directories(nat_type_tester_cli_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(nat_type_tester_cli_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(nat_type_tester_cli_lib PRIVATE -Wall -Wextra -Wpedantic)

add_executable(nat_type_tester_cli main.cpp)
target_link_libraries(nat_type_tester_cli PRIVATE nat_type_tester_cli_lib)

if(BUILD_TESTING)
  add_test(NAME nat_type_tester_cli_tests COMMAND nat_type_tester_cli_tests)
endif()
