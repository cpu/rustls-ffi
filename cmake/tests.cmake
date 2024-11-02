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

add_custom_target(
    integration-test
    DEPENDS client server
    COMMAND
        ${CMAKE_COMMAND} -E env CLIENT_BINARY=${CLIENT_BINARY} ${CMAKE_COMMAND}
        -E env SERVER_BINARY=${SERVER_BINARY} cargo test --locked
        ${CARGO_FEATURES} "$<IF:$<CONFIG:Release>,--release,-->" --test
        client_server client_server_integration -- --ignored --exact
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)
