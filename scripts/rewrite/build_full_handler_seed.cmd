@echo off
setlocal

set "PYTHON_EXE=python"
where %PYTHON_EXE% >nul 2>nul
if errorlevel 1 (
    set "PYTHON_EXE=py"
)

%PYTHON_EXE% "%~dp0build_full_handler_seed.py" %*
exit /b %errorlevel%
