@echo off
setlocal

if "%~1"=="" (
    set "WORKDIR=%~dp0..\..\..\rewrite-regression-work"
) else (
    set "WORKDIR=%~1"
)
for %%I in ("%WORKDIR%") do set "WORKDIR=%%~fI"

if not exist "%WORKDIR%" mkdir "%WORKDIR%"
if not exist "%WORKDIR%\ir_outputs" mkdir "%WORKDIR%\ir_outputs"

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

set "NASM_BIN="
if defined NASM_EXE (
    set "NASM_BIN=%NASM_EXE%"
) else (
    for /f "usebackq delims=" %%I in (`where nasm 2^>nul`) do (
        set "NASM_BIN=%%I"
        goto found_nasm
    )
)

if exist "%~dp0..\..\..\nasm-portable\nasm-3.01\nasm.exe" set "NASM_BIN=%~dp0..\..\..\nasm-portable\nasm-3.01\nasm.exe"

:found_nasm
if not defined NASM_BIN (
    echo ERROR: NASM not found. Install NASM or set NASM_EXE environment variable.
    exit /b 1
)

for %%F in ("%~dp0..\..\testcases\rewrite_smoke\*.asm") do (
    "%NASM_BIN%" -f win64 -gcv8 -o "%WORKDIR%\%%~nF.obj" "%%~fF"
    if errorlevel 1 exit /b 1

    link.exe /nologo /entry:start /subsystem:console /out:"%WORKDIR%\%%~nF.exe" /map:"%WORKDIR%\%%~nF.map" "%WORKDIR%\%%~nF.obj" kernel32.lib
    if errorlevel 1 exit /b 1
)

rem --- Compile C test programs (real binaries with CRT) ---
for %%F in ("%~dp0..\..\testcases\rewrite_smoke\*.c") do (
    cl.exe /nologo /Od /GS- /c /Fo"%WORKDIR%\%%~nF.obj" "%%~fF"
    if errorlevel 1 exit /b 1

    link.exe /nologo /subsystem:console /out:"%WORKDIR%\%%~nF.exe" /map:"%WORKDIR%\%%~nF.map" "%WORKDIR%\%%~nF.obj"
    if errorlevel 1 exit /b 1
)

rem --- Compile C++ test programs (real binaries with CRT + STL) ---
for %%F in ("%~dp0..\..\testcases\rewrite_smoke\*.cpp") do (
    cl.exe /nologo /Od /GS- /EHsc /c /Fo"%WORKDIR%\%%~nF.obj" "%%~fF"
    if errorlevel 1 exit /b 1

    link.exe /nologo /subsystem:console /out:"%WORKDIR%\%%~nF.exe" /map:"%WORKDIR%\%%~nF.map" "%WORKDIR%\%%~nF.obj"
    if errorlevel 1 exit /b 1
)

echo Built rewrite regression samples in "%WORKDIR%"
exit /b 0