@echo off
setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: vswhere.exe not found at "%VSWHERE%"
    exit /b 1
)

set "VSROOT="
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
if not defined VSROOT (
    echo ERROR: Visual Studio installation with VC tools not found
    exit /b 1
)

call "%VSROOT%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1

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

set "LLVM_CMAKE_DIR=%LLVM_DIR%"
if not defined LLVM_CMAKE_DIR (
    if exist "%~dp0..\..\..\llvm18-install\lib\cmake\llvm\LLVMConfig.cmake" set "LLVM_CMAKE_DIR=%~dp0..\..\..\llvm18-install\lib\cmake\llvm"
)
if not defined LLVM_CMAKE_DIR (
    echo ERROR: LLVM_DIR is not set and no local llvm18-install was found
    exit /b 1
)

for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
set "BUILD_DIR=%REPO_ROOT%\build_zydis"

set "MERGEN_C_COMPILER=%CMAKE_C_COMPILER%"
if not defined MERGEN_C_COMPILER set "MERGEN_C_COMPILER=clang-cl"
set "MERGEN_CXX_COMPILER=%CMAKE_CXX_COMPILER%"
if not defined MERGEN_CXX_COMPILER set "MERGEN_CXX_COMPILER=%MERGEN_C_COMPILER%"

if exist "%BUILD_DIR%\CMakeCache.txt" (
    echo INFO: Reconfiguring existing build_zydis cache for Zydis-only lane
    echo INFO: Clearing backend-selection cache keys to prevent stale backend state
    set "CMAKE_CACHE_CLEAR_ARGS=-UICED_* -UCARGO_EXECUTABLE -UBUILD_WITH_ZYDIS"
) else (
    set "CMAKE_CACHE_CLEAR_ARGS="
)

"%CMAKE_BIN%" -G Ninja -S "%REPO_ROOT%" -B "%BUILD_DIR%" -DCMAKE_BUILD_TYPE=Release %CMAKE_CACHE_CLEAR_ARGS% -DLLVM_DIR="%LLVM_CMAKE_DIR%" -DBUILD_WITH_ZYDIS=ON -DCMAKE_C_COMPILER="%MERGEN_C_COMPILER%" -DCMAKE_CXX_COMPILER="%MERGEN_CXX_COMPILER%" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
exit /b %errorlevel%
