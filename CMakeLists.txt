cmake_minimum_required(VERSION 3.15)

project(rustls-ffi DESCRIPTION "C FFI bindings for the Rustls TLS crate")

# Use `cmake -LH $BUILD_DIR` to see all options/help.
# Use `cmake --build $BUILD_DIR --target help` to see all targets.

include(cmake/options.cmake)
include(cmake/rust.cmake)
include(cmake/tests.cmake)
include(cmake/formatting.cmake)

add_subdirectory(tests)
