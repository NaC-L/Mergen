@echo off
setlocal


set "FULL_SEED=%~dp0oracle_seed_full_handlers.json"
set "ENRICHED_SEED=%~dp0oracle_seed_full_handlers_enriched.json"
set "FULL_VECTORS=%~dp0..\..\lifter\test\test_vectors\oracle_vectors_full_handlers.json"

call "%~dp0build_full_handler_seed.cmd" --out-seed "%FULL_SEED%"
if errorlevel 1 exit /b 1

set "PYTHON_EXE=python"
where %PYTHON_EXE% >nul 2>nul
if errorlevel 1 (
    set "PYTHON_EXE=py"
)

%PYTHON_EXE% "%~dp0enrich_seed.py" --seed "%FULL_SEED%" --out "%ENRICHED_SEED%"
if errorlevel 1 exit /b 1

call "%~dp0generate_oracle_vectors.cmd" --seed "%ENRICHED_SEED%" --out "%FULL_VECTORS%"
if errorlevel 1 exit /b 1

set "MERGEN_TEST_VECTORS=%FULL_VECTORS%"
set "SKIP_ORACLE_GENERATION=1"
call "%~dp0run_microtests.cmd" %*
exit /b %errorlevel%
