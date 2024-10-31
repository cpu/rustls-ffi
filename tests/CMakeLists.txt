IF (WIN32)
    add_compile_definitions(
            _WIN32_WINNT=0x601
            _CRT_SECURE_NO_WARNINGS
            _CRT_NONSTDC_NO_WARNINGS
            ssize_t=int
    )
ENDIF (WIN32)

if (CRYPTO_PROVIDER STREQUAL "aws_lc_rs")
    add_compile_definitions(DEFINE_AWS_LC_RS)
elseif (CRYPTO_PROVIDER STREQUAL "ring")
    add_compile_definitions(DEFINE_RING)
endif ()

# Set ASAN sanitizer flags conditionally for Debug builds
set(sanitizer_flags "$<$<CONFIG:Debug>:-fsanitize=address>")
add_compile_options(${sanitizer_flags})

# FIPS-specific setup
if (FIPS STREQUAL "true")
    file(GLOB fips_dll_release_dir "${CMAKE_SOURCE_DIR}/target/release/build/aws-lc-fips-sys-*/out/build/artifacts")
    file(GLOB fips_dll_debug_dir "${CMAKE_SOURCE_DIR}/target/debug/build/aws-lc-fips-sys-*/out/build/artifacts")
    list(GET fips_dll_release_dir 0 fips_dll_release)
    list(GET fips_dll_debug_dir 0 fips_dll_debug)
    set(fips_dll "$<$<CONFIG:Debug>:${fips_dll_debug}>$<$<CONFIG:Release>:${fips_dll_release}>")

    function(copy_fips_dlls target)
        # Add post-build command to copy DLLs
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${fips_dll}/aws_lc_fips_0_12_13_rust_wrapper.dll
                ${fips_dll}/aws_lc_fips_0_12_13_crypto.dll
                $<TARGET_FILE_DIR:${target}>)
    endfunction()
endif()

add_executable(client client.c common.c)
add_dependencies(client rustls-ffi)
target_include_directories(client PUBLIC ${CMAKE_SOURCE_DIR}/src)
IF (WIN32)
    target_link_libraries(
            client
            debug "${CMAKE_SOURCE_DIR}/target/debug/rustls_ffi.lib"
            optimized "${CMAKE_SOURCE_DIR}/target/release/rustls_ffi.lib"
            advapi32.lib bcrypt.lib crypt32.lib cryptnet.lib kernel32.lib ncrypt.lib bcrypt.lib advapi32.lib legacy_stdio_definitions.lib kernel32.lib advapi32.lib kernel32.lib ntdll.lib userenv.lib ws2_32.lib synchronization.lib kernel32.lib ws2_32.lib kernel32.lib msvcrt.lib
    )
    if (FIPS STREQUAL "true")
        target_link_libraries(
            client
            "${fips_dll}/aws_lc_fips_0_12_13_rust_wrapper.lib"
            "${fips_dll}/aws_lc_fips_0_12_13_crypto.lib" 
        )
        copy_fips_dlls(client)
    endif()
    set_property(TARGET client PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
ENDIF (WIN32)
IF (UNIX)
    # TODO
ENDIF (UNIX)
IF (APPLE)
    # TODO
ENDIF (APPLE)

add_executable(server server.c common.c)
add_dependencies(server rustls-ffi)
target_include_directories(server PUBLIC ${CMAKE_SOURCE_DIR}/src)
IF (WIN32)
    target_link_libraries(
            server
            debug "${CMAKE_SOURCE_DIR}/target/debug/rustls_ffi.lib"
            optimized "${CMAKE_SOURCE_DIR}/target/release/rustls_ffi.lib"
            advapi32.lib bcrypt.lib crypt32.lib cryptnet.lib kernel32.lib ncrypt.lib bcrypt.lib advapi32.lib legacy_stdio_definitions.lib kernel32.lib advapi32.lib kernel32.lib ntdll.lib userenv.lib ws2_32.lib synchronization.lib kernel32.lib ws2_32.lib kernel32.lib msvcrt.lib
    )
    if (FIPS STREQUAL "true")
        target_link_libraries(
            server
            "${fips_dll}/aws_lc_fips_0_12_13_rust_wrapper.lib"
            "${fips_dll}/aws_lc_fips_0_12_13_crypto.lib" 
        )
        copy_fips_dlls(server)
    endif()
    set_property(TARGET server PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
ENDIF (WIN32)
IF (UNIX)
    # TODO
ENDIF (UNIX)
IF (APPLE)
    # TODO
ENDIF (APPLE)
