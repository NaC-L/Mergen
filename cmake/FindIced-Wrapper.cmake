

if (BUILD_WITH_ZYDIS)
    message(STATUS "BUILD_WITH_ZYDIS=ON; forcing Zydis backend and skipping Cargo lookup")
    add_compile_definitions(ICED_NOT_FOUND)
    return()
endif()

find_program(CARGO_EXECUTABLE cargo)

if (NOT CARGO_EXECUTABLE)
    message("Cargo not found. Default to Zydis.")
    set(ICED_NOT_FOUND TRUE CACHE BOOL "Rust/Cargo not found => building with the Zydis backend")
    add_compile_definitions(ICED_NOT_FOUND)

    return()
endif()

message("Cargo found. Default to Iced.")

include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/NaC-L/corrosion.git # some issue with linker, i forgot, enabling flag should help?, hopefully my patch doesnt break anything
    GIT_TAG 8b991b7 # Optionally specify a commit hash, version tag or branch here
)

FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH icpped_rust/Cargo.toml)


set(ICED_FOUND TRUE CACHE BOOL "Rust/Cargo found => building with the Iced (Rust) backend")
add_compile_definitions(ICED_FOUND)
