@echo off
setlocal

::resolve_workdir
if "%~1"=="" (
    set "WORKDIR=%~dp0..\..\..\rewrite-regression-work"
 ) else (
    set "WORKDIR=%~1"
 )
for %%I in ("%WORKDIR%") do set "WORKDIR=%%~fI"

::ensure_directories
if not exist "%WORKDIR%" mkdir "%WORKDIR%"
if not exist "%WORKDIR%\ir_outputs" mkdir "%WORKDIR%\ir_outputs"

::resolve_nasm
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

::resolve_clang
set "CLANG_CL_BIN="
if defined CLANG_CL_EXE (
    if exist "%CLANG_CL_EXE%" (
        set "CLANG_CL_BIN=%CLANG_CL_EXE%"
    ) else (
        echo ERROR: CLANG_CL_EXE is set but could not be resolved: %CLANG_CL_EXE%
        exit /b 1
    )
 ) else if defined CMAKE_C_COMPILER (
    if exist "%CMAKE_C_COMPILER%" (
        for %%I in ("%CMAKE_C_COMPILER%") do (
            if /I "%%~nxI"=="clang-cl.exe" (
                set "CLANG_CL_BIN=%%~fI"
            ) else (
                echo INFO: Ignoring CMAKE_C_COMPILER because it is not clang-cl: %CMAKE_C_COMPILER%
            )
        )
    ) else (
        echo ERROR: CMAKE_C_COMPILER is set but could not be resolved: %CMAKE_C_COMPILER%
        exit /b 1
    )
 ) else if defined LLVM_DIR (
    if not exist "%LLVM_DIR%\LLVMConfig.cmake" (
        echo ERROR: LLVM_DIR is set but LLVMConfig.cmake was not found under "%LLVM_DIR%"
        exit /b 1
    )
    for %%I in ("%LLVM_DIR%\..\..\..\bin\clang-cl.exe") do if exist "%%~fI" set "CLANG_CL_BIN=%%~fI"
    if not defined CLANG_CL_BIN echo INFO: LLVM_DIR is set but does not bundle clang-cl; falling back to compiler discovery
 )
if not defined CLANG_CL_BIN if defined CI (
    echo ERROR: CI requires pinned clang-cl via CLANG_CL_EXE, CMAKE_C_COMPILER, or LLVM_DIR. Refusing host fallback.
    exit /b 1
)
if not defined CLANG_CL_BIN if exist "%~dp0..\..\..\llvm18-install\bin\clang-cl.exe" set "CLANG_CL_BIN=%~dp0..\..\..\llvm18-install\bin\clang-cl.exe"
if not defined CLANG_CL_BIN (
    for /f "usebackq delims=" %%I in (`where clang-cl 2^>nul`) do (
        set "CLANG_CL_BIN=%%I"
        goto found_clang
    )
 )
if not defined CLANG_CL_BIN if exist "C:\Program Files\LLVM\bin\clang-cl.exe" set "CLANG_CL_BIN=C:\Program Files\LLVM\bin\clang-cl.exe"

:found_clang
if not defined CLANG_CL_BIN (
    echo ERROR: clang-cl not found. Install LLVM, set LLVM_DIR, or set CLANG_CL_EXE.
    exit /b 1
 )
for %%I in ("%CLANG_CL_BIN%") do set "CLANG_CL_DIR=%%~dpI"
if defined CLANG_CL_DIR set "PATH=%CLANG_CL_DIR%;%PATH%"
echo INFO: Using clang-cl at "%CLANG_CL_BIN%"

::build_asm_samples
for %%F in ("%~dp0..\..\testcases\rewrite_smoke\*.asm") do (
    call :should_skip_build "%%~fF" "%WORKDIR%\%%~nF.obj" "%WORKDIR%\%%~nF.exe" "%WORKDIR%\%%~nF.map"
    if not errorlevel 1 (
        echo SKIP ASM up-to-date: %%~nxF
    ) else (
        "%NASM_BIN%" -f win64 -gcv8 -o "%WORKDIR%\%%~nF.obj" "%%~fF"
        if errorlevel 1 exit /b 1

        "%CLANG_CL_BIN%" /nologo "%WORKDIR%\%%~nF.obj" kernel32.lib /link /entry:start /subsystem:console /out:"%WORKDIR%\%%~nF.exe" /map:"%WORKDIR%\%%~nF.map"
        if errorlevel 1 exit /b 1
    )
 )

::build_c_samples_od
rem --- Compile C test programs (real binaries with CRT) ---
for %%F in ("%~dp0..\..\testcases\rewrite_smoke\*.c") do (
    echo %%~nF | findstr /I "_jumptable" >nul
    if not errorlevel 1 (
        echo SKIP C /Od pass for jumptable sample: %%~nxF
    ) else (
        call :should_skip_build "%%~fF" "%WORKDIR%\%%~nF.obj" "%WORKDIR%\%%~nF.exe" "%WORKDIR%\%%~nF.map"
        if not errorlevel 1 (
            echo SKIP C up-to-date: %%~nxF
        ) else (
            "%CLANG_CL_BIN%" /nologo /Od /GS- /c /Fo"%WORKDIR%\%%~nF.obj" "%%~fF"
            if errorlevel 1 exit /b 1

            "%CLANG_CL_BIN%" /nologo "%WORKDIR%\%%~nF.obj" /link /subsystem:console /out:"%WORKDIR%\%%~nF.exe" /map:"%WORKDIR%\%%~nF.map"
            if errorlevel 1 exit /b 1
        )
    )
 )

::build_c_samples_o2
rem --- Compile jump-table C tests with /O2 (need optimizer for real jmp tables) ---
for %%F in ("%~dp0..\..\testcases\rewrite_smoke\*_jumptable*.c") do (
    call :should_skip_build "%%~fF" "%WORKDIR%\%%~nF.obj" "%WORKDIR%\%%~nF.exe" "%WORKDIR%\%%~nF.map"
    if not errorlevel 1 (
        echo SKIP C /O2 up-to-date: %%~nxF
    ) else (
        "%CLANG_CL_BIN%" /nologo /O2 /GS- /c /Fo"%WORKDIR%\%%~nF.obj" "%%~fF"
        if errorlevel 1 exit /b 1

        "%CLANG_CL_BIN%" /nologo "%WORKDIR%\%%~nF.obj" /link /subsystem:console /out:"%WORKDIR%\%%~nF.exe" /map:"%WORKDIR%\%%~nF.map"
        if errorlevel 1 exit /b 1
    )
 )

::build_cpp_samples
rem --- Compile C++ test programs (real binaries with CRT + STL) ---
for %%F in ("%~dp0..\..\testcases\rewrite_smoke\*.cpp") do (
    call :should_skip_build "%%~fF" "%WORKDIR%\%%~nF.obj" "%WORKDIR%\%%~nF.exe" "%WORKDIR%\%%~nF.map"
    if not errorlevel 1 (
        echo SKIP C++ up-to-date: %%~nxF
    ) else (
        "%CLANG_CL_BIN%" /nologo /Od /GS- /EHsc /c /Fo"%WORKDIR%\%%~nF.obj" "%%~fF"
        if errorlevel 1 exit /b 1

        "%CLANG_CL_BIN%" /nologo "%WORKDIR%\%%~nF.obj" /link /subsystem:console /out:"%WORKDIR%\%%~nF.exe" /map:"%WORKDIR%\%%~nF.map"
        if errorlevel 1 exit /b 1
    )
 )

::done
echo Built rewrite regression samples in "%WORKDIR%"
exit /b 0

:should_skip_build
set "SRC=%~1"
set "OBJ=%~2"
set "EXE=%~3"
set "MAP=%~4"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$src=Get-Item -LiteralPath '%SRC%';" ^
  "$outs=@('%OBJ%','%EXE%','%MAP%');" ^
  "if(($outs | Where-Object { -not (Test-Path -LiteralPath $_) }).Count -gt 0){ exit 1 };" ^
  "$latest=($outs | ForEach-Object { (Get-Item -LiteralPath $_).LastWriteTimeUtc } | Sort-Object -Descending | Select-Object -First 1);" ^
  "if($latest -ge $src.LastWriteTimeUtc){ exit 0 } else { exit 1 }"
exit /b %errorlevel%