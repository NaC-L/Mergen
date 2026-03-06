@echo off
setlocal

call "%~dp0generate_flag_stress_vectors.cmd"
if errorlevel 1 exit /b 1

set "MERGEN_TEST_VECTORS=%~dp0..\..\lifter\test\test_vectors\oracle_vectors_flagstress.json"
set "SKIP_ORACLE_GENERATION=1"
set "MERGEN_TEST_CHECK_FLAGS=1"

call "%~dp0run_microtests.cmd" %*
exit /b %errorlevel%
