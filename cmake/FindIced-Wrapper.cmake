find_program(CARGO_EXECUTABLE cargo)

if (CARGO_EXECUTABLE)
    message("Cargo not found. Default to Zydis")
    return()
endif()

message("Cargo not found. Default to Iced")

include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/NaC-L/corrosion.git
    GIT_TAG 8b991b7 # Optionally specify a commit hash, version tag or branch here
)

FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH icpped_rust/Cargo.toml)


set(ICED_FOUND TRUE CACHE BOOL "Rust/Cargo found => build the iced (Rust) backend")
add_compile_definitions(ICED_FOUND)
