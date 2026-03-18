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

for %%I in ("%~dp0..\..") do set "REPO_ROOT=%%~fI"
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

"%CMAKE_BIN%" --build "%BUILD_DIR%" --config Release --parallel 12
exit /b %errorlevel%
