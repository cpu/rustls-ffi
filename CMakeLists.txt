cmake_minimum_required(VERSION 3.15)

project(rustls-ffi DESCRIPTION "C FFI bindings for the Rustls TLS crate")

set(CRYPTO_PROVIDER
    "aws-lc-rs"
    CACHE STRING
    "Crypto provider to use (aws-lc-rs or ring)"
)

if(
    NOT (CRYPTO_PROVIDER STREQUAL "aws-lc-rs" OR CRYPTO_PROVIDER STREQUAL "ring")
)
    message(
        FATAL_ERROR
        "Invalid crypto provider specified: ${CRYPTO_PROVIDER}. Must be 'aws-lc-rs' or 'ring'."
    )
endif()

option(
    CERT_COMPRESSION
    "Enable brotli and zlib certificate compression support"
)

set(CARGO_FEATURES --no-default-features)
if(CRYPTO_PROVIDER STREQUAL "aws-lc-rs")
    list(APPEND CARGO_FEATURES --features=aws-lc-rs)
elseif(CRYPTO_PROVIDER STREQUAL "ring")
    list(APPEND CARGO_FEATURES --features=ring)
endif()

if(CERT_COMPRESSION)
    list(APPEND CARGO_FEATURES --features=cert_compression)
endif()

# By default w/ Makefile or Ninja generators the CMAKE_BUILD_TYPE is ""
# for the C/C++ tooling. This is annoying so conditionally set it to
# our own default. The `CMAKE_CONFIGURATION_TYPES` check excludes the
# "multi-config" generators like Visual Studio that use --config and
# ignore CMAKE_CONFIGURATION_TYPES.
set(default_build_type "Release")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Using default build type: ${default_build_type}")
    set(CMAKE_BUILD_TYPE
        "${default_build_type}"
        CACHE STRING
        "Choose the type of build."
        FORCE
    )
endif()

add_subdirectory(tests)

include(ExternalProject)
set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/rust)

ExternalProject_Add(
    rustls-ffi
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
        cargo build --locked ${CARGO_FEATURES}
        "$<IF:$<CONFIG:Release>,--release,-->"
    # Rely on cargo checking timestamps, rather than tell CMake where every
    # output is.
    BUILD_ALWAYS true
    INSTALL_COMMAND ""
    # Run cargo test with --quiet because msbuild will treat the presence
    # of "error" in stdout as an error, and we have some test functions that
    # end in "_error". Quiet mode suppresses test names, so this is a
    # sufficient workaround.
    TEST_COMMAND
        cargo test --locked ${CARGO_FEATURES}
        "$<IF:$<CONFIG:Release>,--release,-->" --quiet
)
