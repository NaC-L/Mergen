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
set "BUILD_DIR=%REPO_ROOT%\build_zydis"

if not exist "%BUILD_DIR%\CMakeCache.txt" (
    echo ERROR: Missing "%BUILD_DIR%\CMakeCache.txt". Run scripts\dev\configure_zydis.cmd first.
    exit /b 1
)

findstr /B /C:"ICED_NOT_FOUND:BOOL=TRUE" "%BUILD_DIR%\CMakeCache.txt" >nul
if errorlevel 1 (
    echo ERROR: build_zydis cache is not in Zydis mode; expected ICED_NOT_FOUND:BOOL=TRUE.
    echo ERROR: Re-run scripts\dev\configure_zydis.cmd to avoid stale backend contamination.
    exit /b 1
)

set "BUILD_JOBS=%MERGEN_BUILD_JOBS%"
if not defined BUILD_JOBS set "BUILD_JOBS=4"
"%CMAKE_BIN%" --build "%BUILD_DIR%" --config Release --parallel %BUILD_JOBS%
exit /b %errorlevel%