cmake_minimum_required(VERSION 3.20)
project(mime LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(mime INTERFACE)
add_library(mime::mime ALIAS mime)

target_include_directories(mime INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

if (MSVC)
  target_compile_options(mime INTERFACE /W4 /permissive-)
else()
  target_compile_options(mime INTERFACE -Wall -Wextra -Wpedantic)
endif()

include(CTest)
enable_testing()

add_executable(mime_basic_test tests/test_basic.cpp)
target_link_libraries(mime_basic_test PRIVATE mime::mime)
add_test(NAME mime.basic COMMAND mime_basic_test)
