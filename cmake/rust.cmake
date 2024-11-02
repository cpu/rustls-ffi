include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.5
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(
        MANIFEST_PATH Cargo.toml
        PROFILE "$<IF:$<CONFIG:Release>,release,dev>"
        NO_DEFAULT_FEATURES
        FEATURES ${CARGO_FEATURES}
)

add_custom_target(
    cbindgen
    COMMAND cbindgen > "src/rustls.h"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_custom_target(
    connect-test
    DEPENDS client
    COMMAND
        ${CMAKE_COMMAND} -E env RUSTLS_PLATFORM_VERIFIER=1
        ${CMAKE_BINARY_DIR}/tests/client example.com 443 /
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

if(WIN32)
    set(CLIENT_BINARY "${CMAKE_BINARY_DIR}\\tests\\$<CONFIG>\\client.exe")
    set(SERVER_BINARY "${CMAKE_BINARY_DIR}\\tests\\$<CONFIG>\\server.exe")
else()
    set(CLIENT_BINARY "${CMAKE_BINARY_DIR}/tests/client")
    set(SERVER_BINARY "${CMAKE_BINARY_DIR}/tests/server")
endif()

string(JOIN "," CARGO_FEATURES_STR ${CARGO_FEATURES})
add_custom_target(
    integration-test
    DEPENDS client server
    COMMAND
        ${CMAKE_COMMAND} -E env CLIENT_BINARY=${CLIENT_BINARY} ${CMAKE_COMMAND}
        -E env SERVER_BINARY=${SERVER_BINARY} cargo test --locked --features
        "${CARGO_FEATURES_STR}" "$<IF:$<CONFIG:Release>,--release,>" --test
        client_server client_server_integration -- --ignored --exact
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
