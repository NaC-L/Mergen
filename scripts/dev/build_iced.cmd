@echo off
setlocal

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

for %%I in ("%~dp0..\.." ) do set "REPO_ROOT=%%~fI"

if not exist "%REPO_ROOT%\build_iced\CMakeCache.txt" (
    echo ERROR: build_iced not configured. Run scripts\dev\configure_iced.cmd first.
    exit /b 1
)

set "BUILD_JOBS=%MERGEN_BUILD_JOBS%"
if not defined BUILD_JOBS set "BUILD_JOBS=4"
"%CMAKE_BIN%" --build "%REPO_ROOT%\build_iced" --config Release --parallel %BUILD_JOBS%
exit /b %errorlevel%