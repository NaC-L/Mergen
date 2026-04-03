@echo off
setlocal EnableDelayedExpansion

rem --- clang-cl auto-detects MSVC headers/libs; no VsDevCmd needed ---

::resolve_cargo
set "CARGO_BIN="
set "CARGO_EXE="
if defined CARGO_EXECUTABLE if exist "%CARGO_EXECUTABLE%" set "CARGO_EXE=%CARGO_EXECUTABLE%"
if not defined CARGO_EXE if defined CARGO_HOME if exist "%CARGO_HOME%\bin\cargo.exe" set "CARGO_EXE=%CARGO_HOME%\bin\cargo.exe"
if not defined CARGO_EXE if defined USERPROFILE if exist "%USERPROFILE%\.cargo\bin\cargo.exe" set "CARGO_EXE=%USERPROFILE%\.cargo\bin\cargo.exe"
if defined CARGO_EXE for %%I in ("%CARGO_EXE%") do set "CARGO_BIN=%%~dpI"
if defined CARGO_BIN set "PATH=%CARGO_BIN%;%PATH%"
set "CMAKE_CARGO_ARG="
if defined CARGO_EXE set "CMAKE_CARGO_ARG=-DCARGO_EXECUTABLE=%CARGO_EXE%"
set "RUST_TOOLCHAIN_ARG="
if defined CARGO_EXE (
    for /f "tokens=1" %%I in ('rustup show active-toolchain 2^>nul') do set "MERGEN_RUST_TOOLCHAIN=%%I"
    if defined MERGEN_RUST_TOOLCHAIN set "RUST_TOOLCHAIN_ARG=-DRust_TOOLCHAIN=!MERGEN_RUST_TOOLCHAIN!"
    set "MERGEN_RUST_TOOLCHAIN="
 )

:resolve_cmake
set "CMAKE_BIN="
for /f "usebackq delims=" %%I in (`where cmake 2^>nul`) do (
    set "CMAKE_BIN=%%I"
    goto found_cmake
)
if exist "C:\Program Files\CMake\bin\cmake.exe" set "CMAKE_BIN=C:\Program Files\CMake\bin\cmake.exe"

:found_cmake
if not defined CMAKE_BIN (
    echo ERROR: CMake not found in PATH
    exit /b 1
)

:resolve_llvm
set "LLVM_CMAKE_DIR=%LLVM_DIR%"
if not defined LLVM_CMAKE_DIR (
    if exist "%~dp0..\..\..\llvm18-install\lib\cmake\llvm\LLVMConfig.cmake" set "LLVM_CMAKE_DIR=%~dp0..\..\..\llvm18-install\lib\cmake\llvm"
)
if not defined LLVM_CMAKE_DIR (
    echo ERROR: LLVM_DIR is not set and no local llvm18-install was found
    exit /b 1
)

:resolve_compiler
for %%I in ("%~dp0..\.." ) do set "REPO_ROOT=%%~fI"

set "MERGEN_C_COMPILER=%CMAKE_C_COMPILER%"
if not defined MERGEN_C_COMPILER set "MERGEN_C_COMPILER=clang-cl"
set "MERGEN_CXX_COMPILER=%CMAKE_CXX_COMPILER%"
if not defined MERGEN_CXX_COMPILER set "MERGEN_CXX_COMPILER=%MERGEN_C_COMPILER%"

::configure
"%CMAKE_BIN%" -G Ninja -S "%REPO_ROOT%" -B "%REPO_ROOT%\build_iced" -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR="%LLVM_CMAKE_DIR%" -DCMAKE_C_COMPILER="%MERGEN_C_COMPILER%" -DCMAKE_CXX_COMPILER="%MERGEN_CXX_COMPILER%" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON %CMAKE_CARGO_ARG% %RUST_TOOLCHAIN_ARG%
exit /b %errorlevel%