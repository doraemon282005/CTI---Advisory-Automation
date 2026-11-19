@echo off
setlocal EnableDelayedExpansion

:: Change to script directory (handling spaces in path)
cd /d "%~dp0"

echo [CTI Advisory Surveillance] Running FULL SCAN (re-evaluating all articles from feed)...
py -3 "src\pipeline.py" --force
set "EXIT_CODE=%ERRORLEVEL%"

if not "!EXIT_CODE!"=="0" (
    echo [ERROR] Pipeline encountered an error with exit code !EXIT_CODE!.
    pause
    exit /b !EXIT_CODE!
)

echo [SUCCESS] Full scan completed successfully.
pause
exit /b 0
