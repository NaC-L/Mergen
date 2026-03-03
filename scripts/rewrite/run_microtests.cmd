@echo off
setlocal

if /I "%~1"=="--check-flags" (
    set "CHECK_FLAGS=1"
    shift
)

call "%~dp0..\dev\build_iced.cmd"
if errorlevel 1 exit /b 1

set "CMAKE_EXE=%ProgramFiles%\CMake\bin\cmake.exe"
if not exist "%CMAKE_EXE%" (
    echo ERROR: CMake executable not found at "%CMAKE_EXE%"
    exit /b 1
)

"%CMAKE_EXE%" --build "%~dp0..\..\build_iced" --target rewrite_microtests
if errorlevel 1 exit /b 1

if /I not "%SKIP_ORACLE_GENERATION%"=="1" (
    call "%~dp0generate_oracle_vectors.cmd"
    if errorlevel 1 exit /b 1
)

set "MICROTEST_EXE=%~dp0..\..\build_iced\rewrite_microtests.exe"
if not exist "%MICROTEST_EXE%" (
    echo ERROR: rewrite_microtests executable not found at "%MICROTEST_EXE%"
    exit /b 1
)

if /I "%CHECK_FLAGS%"=="1" (
    set "MERGEN_TEST_CHECK_FLAGS=1"
    echo Enabling strict oracle flag checks
 )

"%MICROTEST_EXE%" %*
exit /b %errorlevel%
