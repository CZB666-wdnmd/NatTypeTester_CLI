cmake_minimum_required(VERSION 3.20)
project(NatTypeTesterServer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(nat_type_tester_rfc5382_server main.cpp)
target_compile_options(nat_type_tester_rfc5382_server PRIVATE -Wall -Wextra -Wpedantic)
