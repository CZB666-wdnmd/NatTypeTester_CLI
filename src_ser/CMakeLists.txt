cmake_minimum_required(VERSION 3.20)
project(NatTypeTesterServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(nat_type_tester_server main.cpp)
target_compile_options(nat_type_tester_server PRIVATE -Wall -Wextra -Wpedantic)

target_link_libraries(nat_type_tester_server PRIVATE OpenSSL::SSL OpenSSL::Crypto)
