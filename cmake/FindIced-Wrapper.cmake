# Keep backend selection deterministic across cache reconfiguration cycles.
# We only ever want one of ICED_FOUND / ICED_NOT_FOUND compile definitions active.
remove_definitions(-DICED_FOUND -DICED_NOT_FOUND)

if (BUILD_WITH_ZYDIS)
    message(STATUS "BUILD_WITH_ZYDIS=ON; forcing Zydis backend and skipping Cargo lookup")
    set(ICED_NOT_FOUND TRUE CACHE BOOL "BUILD_WITH_ZYDIS forces Zydis backend" FORCE)
    set(ICED_FOUND FALSE CACHE BOOL "BUILD_WITH_ZYDIS disables Iced backend" FORCE)
    add_compile_definitions(ICED_NOT_FOUND)
    return()
endif()

# Avoid stale find_program cache entries when toggling toolchains/workspaces.
unset(CARGO_EXECUTABLE CACHE)
unset(_MERGEN_CARGO_EXECUTABLE CACHE)
find_program(_MERGEN_CARGO_EXECUTABLE NAMES cargo)

if (NOT _MERGEN_CARGO_EXECUTABLE OR NOT EXISTS "${_MERGEN_CARGO_EXECUTABLE}")
    message(STATUS "Cargo not found. Defaulting to Zydis backend.")
    unset(CARGO_EXECUTABLE CACHE)
    set(ICED_NOT_FOUND TRUE CACHE BOOL "Rust/Cargo not found => building with the Zydis backend" FORCE)
    set(ICED_FOUND FALSE CACHE BOOL "Rust/Cargo not found => Iced backend disabled" FORCE)
    add_compile_definitions(ICED_NOT_FOUND)
    return()
endif()

set(CARGO_EXECUTABLE "${_MERGEN_CARGO_EXECUTABLE}" CACHE FILEPATH "Resolved cargo executable" FORCE)
message(STATUS "Cargo found at ${CARGO_EXECUTABLE}. Defaulting to Iced backend.")

include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/NaC-L/corrosion.git # some issue with linker, i forgot, enabling flag should help?, hopefully my patch doesnt break anything
    GIT_TAG 8b991b7 # Optionally specify a commit hash, version tag or branch here
)

FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH icpped_rust/Cargo.toml)

set(ICED_FOUND TRUE CACHE BOOL "Rust/Cargo found => building with the Iced (Rust) backend" FORCE)
set(ICED_NOT_FOUND FALSE CACHE BOOL "Rust/Cargo found => Zydis fallback disabled" FORCE)
add_compile_definitions(ICED_FOUND)