@echo off
setlocal

:setup
set "SCRIPT_DIR=%~dp0"
set "CHECK_FLAGS="
set "NO_BUILD="
set "FORCE_BUILD="
set "FORWARD_ARGS="
set "MICROTEST_EXE=%SCRIPT_DIR%..\..\build_iced\rewrite_microtests.exe"

:parse_args
if "%~1"=="" goto args_done
if /I "%~1"=="--check-flags" (
    set "CHECK_FLAGS=1"
    shift
    goto parse_args
)
if /I "%~1"=="--no-build" (
    set "NO_BUILD=1"
    shift
    goto parse_args
)
if /I "%~1"=="--build" (
    set "FORCE_BUILD=1"
    shift
    goto parse_args
)
set "FORWARD_ARGS=%FORWARD_ARGS% %~1"
shift
goto parse_args

:args_done
if /I not "%NO_BUILD%"=="1" (
    if /I "%FORCE_BUILD%"=="1" (
        call :build_microtests
        if errorlevel 1 exit /b 1
    ) else if not exist "%MICROTEST_EXE%" (
        call :build_microtests
        if errorlevel 1 exit /b 1
    ) else (
        echo SKIP microtests build: existing executable "%MICROTEST_EXE%"
    )
)

:ensure_oracle
if /I not "%SKIP_ORACLE_GENERATION%"=="1" (
    call "%SCRIPT_DIR%generate_oracle_vectors.cmd"
    if errorlevel 1 exit /b 1
)

:ensure_executable
if not exist "%MICROTEST_EXE%" (
    echo ERROR: rewrite_microtests executable not found at "%MICROTEST_EXE%"
    echo Run "%SCRIPT_DIR%run_microtests.cmd --build" or configure/build build_iced first.
    exit /b 1
)

:run_tests
if /I "%CHECK_FLAGS%"=="1" (
    set "MERGEN_TEST_CHECK_FLAGS=1"
    echo Enabling strict oracle flag checks
)

"%MICROTEST_EXE%"%FORWARD_ARGS%
exit /b %errorlevel%

:build_microtests
if not exist "%SCRIPT_DIR%..\..\build_iced\CMakeCache.txt" (
    call "%SCRIPT_DIR%..\dev\configure_iced.cmd"
    if errorlevel 1 exit /b 1
)

set "CMAKE_EXE="
for /f "usebackq delims=" %%I in (`where cmake 2^>nul`) do if not defined CMAKE_EXE set "CMAKE_EXE=%%I"
if not defined CMAKE_EXE if exist "C:\Program Files\CMake\bin\cmake.exe" set "CMAKE_EXE=C:\Program Files\CMake\bin\cmake.exe"
if not defined CMAKE_EXE (
    echo ERROR: CMake executable not found in PATH
    exit /b 1
)

set "BUILD_JOBS=%MERGEN_BUILD_JOBS%"
if not defined BUILD_JOBS set "BUILD_JOBS=4"
"%CMAKE_EXE%" --build "%SCRIPT_DIR%..\..\build_iced" --config Release --target rewrite_microtests --parallel %BUILD_JOBS%
exit /b %errorlevel%