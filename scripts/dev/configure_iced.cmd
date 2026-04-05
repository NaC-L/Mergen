@echo off
setlocal EnableDelayedExpansion

rem --- clang-cl auto-detects MSVC headers/libs; no VsDevCmd needed ---

::resolve_cargo
set "CARGO_BIN="
set "CARGO_EXE="
if defined CARGO_EXECUTABLE (
    if exist "%CARGO_EXECUTABLE%" (
        set "CARGO_EXE=%CARGO_EXECUTABLE%"
    ) else (
        echo ERROR: CARGO_EXECUTABLE is set but could not be resolved: %CARGO_EXECUTABLE%
        exit /b 1
    )
)
if not defined CARGO_EXE if defined CARGO_HOME if exist "%CARGO_HOME%\bin\cargo.exe" set "CARGO_EXE=%CARGO_HOME%\bin\cargo.exe"
if not defined CARGO_EXE if defined USERPROFILE if exist "%USERPROFILE%\.cargo\bin\cargo.exe" set "CARGO_EXE=%USERPROFILE%\.cargo\bin\cargo.exe"
if not defined CARGO_EXE (
    for /f "usebackq delims=" %%I in (`where cargo 2^>nul`) do (
        set "CARGO_EXE=%%I"
        goto found_cargo
    )
)
:found_cargo
if defined CARGO_EXE for %%I in ("%CARGO_EXE%") do set "CARGO_BIN=%%~dpI"
if defined CARGO_BIN set "PATH=%CARGO_BIN%;%PATH%"
set "CMAKE_CARGO_ARG="
if defined CARGO_EXE set CMAKE_CARGO_ARG="-DCARGO_EXECUTABLE=%CARGO_EXE%"
set "MERGEN_RUST_TOOLCHAIN="
if defined RUSTUP_TOOLCHAIN set "MERGEN_RUST_TOOLCHAIN=%RUSTUP_TOOLCHAIN%"
if not defined MERGEN_RUST_TOOLCHAIN if defined CARGO_EXE (
    for /f "tokens=1" %%I in ('rustup show active-toolchain 2^>nul') do (
        set "MERGEN_RUST_TOOLCHAIN=%%I"
        goto found_rust_toolchain
    )
)
:found_rust_toolchain
set "RUST_TOOLCHAIN_ARG="
if defined MERGEN_RUST_TOOLCHAIN set "RUST_TOOLCHAIN_ARG=-DRust_TOOLCHAIN=!MERGEN_RUST_TOOLCHAIN!"

::resolve_cmake
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

::resolve_llvm
set "LLVM_CMAKE_DIR=%LLVM_DIR%"
if defined LLVM_CMAKE_DIR if not exist "%LLVM_CMAKE_DIR%\LLVMConfig.cmake" (
    echo ERROR: LLVM_DIR is set but LLVMConfig.cmake was not found under "%LLVM_CMAKE_DIR%"
    exit /b 1
)
if not defined LLVM_CMAKE_DIR (
    if exist "%~dp0..\..\..\llvm18-install\lib\cmake\llvm\LLVMConfig.cmake" set "LLVM_CMAKE_DIR=%~dp0..\..\..\llvm18-install\lib\cmake\llvm"
)
if not defined LLVM_CMAKE_DIR (
    echo ERROR: LLVM_DIR is not set and no local llvm18-install was found
    exit /b 1
)

::resolve_compiler
for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
set "BUILD_DIR=%REPO_ROOT%\build_iced"
set "LLVM_CLANG_CL="
for %%I in ("%LLVM_CMAKE_DIR%\..\..\..\bin\clang-cl.exe") do if exist "%%~fI" set "LLVM_CLANG_CL=%%~fI"

set "MERGEN_C_COMPILER="
if defined CLANG_CL_EXE (
    if exist "%CLANG_CL_EXE%" (
        set "MERGEN_C_COMPILER=%CLANG_CL_EXE%"
    ) else (
        echo ERROR: CLANG_CL_EXE is set but could not be resolved: %CLANG_CL_EXE%
        exit /b 1
    )
)
if not defined MERGEN_C_COMPILER if defined CMAKE_C_COMPILER (
    if exist "%CMAKE_C_COMPILER%" (
        for %%I in ("%CMAKE_C_COMPILER%") do (
            if /I "%%~nxI"=="clang-cl.exe" (
                set "MERGEN_C_COMPILER=%%~fI"
            ) else (
                echo INFO: Ignoring CMAKE_C_COMPILER because it is not clang-cl: %CMAKE_C_COMPILER%
            )
        )
    ) else (
        echo ERROR: CMAKE_C_COMPILER is set but could not be resolved: %CMAKE_C_COMPILER%
        exit /b 1
    )
)
if not defined MERGEN_C_COMPILER if defined LLVM_CLANG_CL set "MERGEN_C_COMPILER=%LLVM_CLANG_CL%"
if not defined MERGEN_C_COMPILER (
    for /f "usebackq delims=" %%I in (`where clang-cl 2^>nul`) do (
        set "MERGEN_C_COMPILER=%%I"
        goto found_c_compiler
    )
)
if not defined MERGEN_C_COMPILER if exist "C:\Program Files\LLVM\bin\clang-cl.exe" set "MERGEN_C_COMPILER=C:\Program Files\LLVM\bin\clang-cl.exe"
:found_c_compiler
if not defined MERGEN_C_COMPILER (
    echo ERROR: clang-cl not found. Install LLVM, set LLVM_DIR, or set CLANG_CL_EXE.
    exit /b 1
)

set "MERGEN_CXX_COMPILER="
if defined CLANG_CL_EXE (
    if exist "%CLANG_CL_EXE%" (
        set "MERGEN_CXX_COMPILER=%CLANG_CL_EXE%"
    ) else (
        echo ERROR: CLANG_CL_EXE is set but could not be resolved: %CLANG_CL_EXE%
        exit /b 1
    )
)
if not defined MERGEN_CXX_COMPILER if defined CMAKE_CXX_COMPILER (
    if exist "%CMAKE_CXX_COMPILER%" (
        for %%I in ("%CMAKE_CXX_COMPILER%") do (
            if /I "%%~nxI"=="clang-cl.exe" (
                set "MERGEN_CXX_COMPILER=%%~fI"
            ) else (
                echo INFO: Ignoring CMAKE_CXX_COMPILER because it is not clang-cl: %CMAKE_CXX_COMPILER%
            )
        )
    ) else (
        echo ERROR: CMAKE_CXX_COMPILER is set but could not be resolved: %CMAKE_CXX_COMPILER%
        exit /b 1
    )
)
if not defined MERGEN_CXX_COMPILER if defined LLVM_CLANG_CL set "MERGEN_CXX_COMPILER=%LLVM_CLANG_CL%"
if not defined MERGEN_CXX_COMPILER set "MERGEN_CXX_COMPILER=%MERGEN_C_COMPILER%"
for %%I in ("%MERGEN_C_COMPILER%") do set "MERGEN_COMPILER_BIN=%%~dpI"
if defined MERGEN_COMPILER_BIN set "PATH=%MERGEN_COMPILER_BIN%;%PATH%"
echo INFO: Using LLVM_DIR=%LLVM_CMAKE_DIR%
echo INFO: Using C compiler=%MERGEN_C_COMPILER%
echo INFO: Using CXX compiler=%MERGEN_CXX_COMPILER%

::resolve_cache
set "CMAKE_CACHE_CLEAR_ARGS="
if exist "%BUILD_DIR%\CMakeCache.txt" (
    echo INFO: Reconfiguring existing build_iced cache for iced lane
    set "CMAKE_CACHE_CLEAR_ARGS=-UICED_* -UCARGO_EXECUTABLE -URust_TOOLCHAIN -UBUILD_WITH_ZYDIS"
    set "CACHED_C_COMPILER="
    set "CACHED_CXX_COMPILER="
    set "CACHED_LLVM_DIR="
    set "RESET_BUILD_CACHE="
    for /f "tokens=1,* delims==" %%A in ('findstr /B /R /C:"CMAKE_C_COMPILER:[^=]*=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_C_COMPILER=%%B"
    for /f "tokens=1,* delims==" %%A in ('findstr /B /R /C:"CMAKE_CXX_COMPILER:[^=]*=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_CXX_COMPILER=%%B"
    for /f "tokens=1,* delims==" %%A in ('findstr /B /R /C:"LLVM_DIR:[^=]*=" "%BUILD_DIR%\CMakeCache.txt"') do set "CACHED_LLVM_DIR=%%B"
    if defined CACHED_C_COMPILER if /I not "!CACHED_C_COMPILER!"=="!MERGEN_C_COMPILER!" set "RESET_BUILD_CACHE=1"
    if defined CACHED_CXX_COMPILER if /I not "!CACHED_CXX_COMPILER!"=="!MERGEN_CXX_COMPILER!" set "RESET_BUILD_CACHE=1"
    if defined CACHED_LLVM_DIR if /I not "!CACHED_LLVM_DIR!"=="!LLVM_CMAKE_DIR!" set "RESET_BUILD_CACHE=1"
    if defined RESET_BUILD_CACHE (
        echo INFO: Clearing build_iced cache because the requested toolchain changed
        if exist "%BUILD_DIR%\CMakeCache.txt" del /f /q "%BUILD_DIR%\CMakeCache.txt"
        if exist "%BUILD_DIR%\CMakeFiles" rmdir /s /q "%BUILD_DIR%\CMakeFiles"
        set "CMAKE_CACHE_CLEAR_ARGS="
    )
)

::configure
"%CMAKE_BIN%" -G Ninja -S "%REPO_ROOT%" -B "%BUILD_DIR%" -DCMAKE_BUILD_TYPE=Release %CMAKE_CACHE_CLEAR_ARGS% -DLLVM_DIR="%LLVM_CMAKE_DIR%" -DCMAKE_C_COMPILER="%MERGEN_C_COMPILER%" -DCMAKE_CXX_COMPILER="%MERGEN_CXX_COMPILER%" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON %CMAKE_CARGO_ARG% %RUST_TOOLCHAIN_ARG%
exit /b %errorlevel%