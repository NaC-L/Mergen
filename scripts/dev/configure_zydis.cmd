@echo off
setlocal

rem --- clang-cl auto-detects MSVC headers/libs; no VsDevCmd needed ---

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

::resolve_compiler
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
set "BUILD_DIR=%REPO_ROOT%\build_zydis"
set "LLVM_CLANG_CL="
for %%I in ("%LLVM_CMAKE_DIR%\..\..\..\bin\clang-cl.exe") do if exist "%%~fI" set "LLVM_CLANG_CL=%%~fI"

set "MERGEN_C_COMPILER=%CMAKE_C_COMPILER%"
if not defined MERGEN_C_COMPILER if defined CLANG_CL_EXE set "MERGEN_C_COMPILER=%CLANG_CL_EXE%"
if not defined MERGEN_C_COMPILER if defined LLVM_CLANG_CL set "MERGEN_C_COMPILER=%LLVM_CLANG_CL%"
if not defined MERGEN_C_COMPILER set "MERGEN_C_COMPILER=clang-cl"
set "MERGEN_CXX_COMPILER=%CMAKE_CXX_COMPILER%"
if not defined MERGEN_CXX_COMPILER if defined CLANG_CL_EXE set "MERGEN_CXX_COMPILER=%CLANG_CL_EXE%"
if not defined MERGEN_CXX_COMPILER if defined LLVM_CLANG_CL set "MERGEN_CXX_COMPILER=%LLVM_CLANG_CL%"
if not defined MERGEN_CXX_COMPILER set "MERGEN_CXX_COMPILER=%MERGEN_C_COMPILER%"

:configure
if exist "%BUILD_DIR%\CMakeCache.txt" (
    echo INFO: Reconfiguring existing build_zydis cache for Zydis-only lane
    echo INFO: Clearing backend-selection cache keys to prevent stale backend state
    set "CMAKE_CACHE_CLEAR_ARGS=-UICED_* -UCARGO_EXECUTABLE -UBUILD_WITH_ZYDIS"
) else (
    set "CMAKE_CACHE_CLEAR_ARGS="
)

"%CMAKE_BIN%" -G Ninja -S "%REPO_ROOT%" -B "%BUILD_DIR%" -DCMAKE_BUILD_TYPE=Release %CMAKE_CACHE_CLEAR_ARGS% -DLLVM_DIR="%LLVM_CMAKE_DIR%" -DBUILD_WITH_ZYDIS=ON -DCMAKE_C_COMPILER="%MERGEN_C_COMPILER%" -DCMAKE_CXX_COMPILER="%MERGEN_CXX_COMPILER%" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
exit /b %errorlevel%