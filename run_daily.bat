@echo off
setlocal EnableDelayedExpansion

:: Change to script directory (handling spaces in path)
cd /d "%~dp0"

echo [CTI Advisory Surveillance] Starting daily cycle...
py -3 "src\pipeline.py"
set "EXIT_CODE=%ERRORLEVEL%"

if not "!EXIT_CODE!"=="0" (
    echo [ERROR] Pipeline encountered an error with exit code !EXIT_CODE!.
    pause
    exit /b !EXIT_CODE!
)

echo [SUCCESS] Daily advisory processing finished successfully.
exit /b 0
