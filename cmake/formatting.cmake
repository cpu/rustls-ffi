add_custom_target(
    rust-format-fix
    COMMAND sed -i -e 's/ffi_panic_boundary! {/if true {/g' src/*.rs
    COMMAND $<TARGET_FILE:Rust::Cargo> fmt
    COMMAND sed -i -e 's/if true {/ffi_panic_boundary! {/g' src/*.rs
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_custom_target(
    rust-format-check
    COMMAND sed -i -e 's/ffi_panic_boundary! {/if true {/g' src/*.rs
    COMMAND $<TARGET_FILE:Rust::Cargo> fmt --check
    COMMAND sed -i -e 's/if true {/ffi_panic_boundary! {/g' src/*.rs
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_custom_target(
    cmake-format-fix
    COMMAND
        gersemi --no-warn-about-unknown-commands -i CMakeLists.txt cmake/*.cmake
        tests/CMakeLists.txt
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_custom_target(
    cmake-format-check
    COMMAND
        gersemi --no-warn-about-unknown-commands -c CMakeLists.txt cmake/*.cmake
        tests/CMakeLists.txt
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

add_custom_target(
    format-fix
    DEPENDS rust-format-fix c-format-fix cmake-format-fix
)

add_custom_target(
    format-check
    DEPENDS rust-format-check c-format-check cmake-format-check
)

function(add_c_format_targets targets)
    set(all_sources "")
    foreach(target ${targets})
        list(APPEND all_sources $<TARGET_PROPERTY:${target},SOURCES>)
    endforeach()

    # A fix target that formats the source files in-place.
    add_custom_target(
        c-format-fix
        COMMAND clang-format -i ${all_sources}
        COMMAND_EXPAND_LISTS
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    )

    # A check target that checks if the source files are formatted correctly.
    add_custom_target(
        c-format-check
        COMMAND clang-format --dry-run -Werror -i ${all_sources}
        COMMAND_EXPAND_LISTS
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    )
endfunction()

# Add c-format-fix and c-format-check targets for the test binary sourcecode.
add_c_format_targets("client;server")
