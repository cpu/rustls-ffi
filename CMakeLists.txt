cmake_minimum_required(VERSION 3.15)

project(rustls-ffi)

set(CRYPTO_PROVIDER "" CACHE STRING "Crypto provider to use (ring or aws_lc_rs)")

if (NOT (CRYPTO_PROVIDER STREQUAL "ring" OR CRYPTO_PROVIDER STREQUAL "aws_lc_rs"))
    message(FATAL_ERROR "Invalid crypto provider specified: ${CRYPTO_PROVIDER}. Must be 'ring' or 'aws_lc_rs'.")
endif ()

set(CARGO_FEATURES --no-default-features)
if (CRYPTO_PROVIDER STREQUAL "ring")
    list(APPEND CARGO_FEATURES --features=ring)
elseif (CRYPTO_PROVIDER STREQUAL "aws_lc_rs")
    list(APPEND CARGO_FEATURES --features=aws_lc_rs)
endif ()

add_subdirectory(tests)

include(ExternalProject)
set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/rust)

ExternalProject_Add(
        rustls-ffi
        DOWNLOAD_COMMAND ""
        CONFIGURE_COMMAND ""
        BUILD_COMMAND ""
        COMMAND cargo build --locked ${CARGO_FEATURES} "$<IF:$<CONFIG:Release>,--release,-->"
        # Rely on cargo checking timestamps, rather than tell CMake where every
        # output is.
        BUILD_ALWAYS true
        INSTALL_COMMAND ""
        # Run cargo test with --quiet because msbuild will treat the presence
        # of "error" in stdout as an error, and we have some test functions that
        # end in "_error". Quiet mode suppresses test names, so this is a
        # sufficient workaround.
        TEST_COMMAND cargo test --locked ${CARGO_FEATURES} "$<IF:$<CONFIG:Release>,--release,-->" --quiet
)
