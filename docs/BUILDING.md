# Building Mergen

This file owns build and toolchain setup. For pipeline details, use `ARCHITECTURE.md`. For rewrite/test workflows, use `docs/REWRITE_BASELINE.md`.

## Preferred Development Flow
Mergen is developed and CI-tested primarily on Windows with Ninja, `clang-cl`, and LLVM 18.

### Prerequisites
- CMake on `PATH`
- Ninja on `PATH`
- Visual Studio C++ toolchain installed (the scripts rely on `clang-cl` finding MSVC headers/libs; they do not call `VsDevCmd.bat`)
- `LLVM_DIR` pointing at LLVM 18 CMake config, or a local `../llvm18-install/lib/cmake/llvm`
- Rust/Cargo on `PATH` for the default iced backend

### Default iced backend
```bat
cmd /c scripts\dev\configure_iced.cmd
cmd /c scripts\dev\build_iced.cmd
```

Outputs:
- `build_iced/lifter.exe`
- `build_iced/rewrite_microtests.exe`

### Alternate Zydis-only backend
Use this only when you need the fallback lane or backend-specific debugging.

```bat
cmd /c scripts\dev\configure_zydis.cmd
cmd /c scripts\dev\build_zydis.cmd
```

## Verify After Building
Primary checks:

The rewrite gate's sample-build lane is stricter than the core CMake build. CI requires a pinned `clang-cl` via `CLANG_CL_EXE`, `CMAKE_C_COMPILER`, or `LLVM_DIR`; for local `python test.py quick` / `all` runs, set `CLANG_CL_EXE=C:\Program Files\LLVM\bin\clang-cl.exe` when you want the same sample-build compiler resolution as CI instead of relying on local fallback discovery.

```bat
python test.py quick
python test.py all
```

Useful targeted checks:

```bat
python test.py baseline
python test.py micro --check-flags
python test.py negative
python test.py vmp
```

Use `python test.py vmp` for larger control-flow/semantics/inlining changes when you want a quick sanity pass over the local VMProtect targets without making it part of the default `quick` gate. Required 3.8.x targets must finish with `blocks_completed > 0`; the older VMP 3.6 sample remains best-effort only.

## Useful Environment Variables
- `LLVM_DIR` — points CMake at `LLVMConfig.cmake`
- `MERGEN_BUILD_JOBS` — overrides build parallelism (default `4`)
- `CMAKE_C_COMPILER` / `CMAKE_CXX_COMPILER` — optional compiler override for the configure scripts
- `CLANG_CL_EXE` — optional local override for the rewrite gate's sample-build path; set it to the pinned `clang-cl` when you want local `python test.py quick` / `all` runs to match CI compiler resolution

Example:

```bat
set CLANG_CL_EXE=C:\Program Files\LLVM\bin\clang-cl.exe
set MERGEN_BUILD_JOBS=8
cmd /c scripts\dev\build_iced.cmd
python test.py quick
```

## Secondary Flows
### Docker
The checked-in `Dockerfile` is primarily a build/export container: its default `CMD` copies the built `lifter` binary to `/output/lifter`.

```bash
docker build . -t mergen
mkdir -p output
docker run --rm -v "$PWD/output":/output mergen
```

If you want to run the built lifter inside the container instead of exporting it, override the command explicitly:

```bash
docker run --rm -v "$PWD":/work mergen /root/Mergen/build/lifter /work/target.exe 0x123456789
```

### Manual CMake
Use direct CMake only when debugging cmkr/CMake behavior. Day-to-day development should go through `scripts/dev/*.cmd`.

```bat
cmake -G Ninja -S . -B build_iced -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR="..."
cmake --build build_iced --config Release --parallel 4
```

## Build Configuration Boundaries
- `cmake.toml` is the source of truth.
- `CMakeLists.txt` is generated from `cmake.toml`; do not hand-edit it.
- `build*/` directories are generated outputs, not source-controlled configuration.
