@echo off
setlocal EnableDelayedExpansion

:: Change to script directory (handling spaces in path)
cd /d "%~dp0"

echo [CTI Advisory Surveillance] Running FULL SCAN (re-evaluating all articles from feed)...
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -u "src\pipeline.py" --force
) else if exist "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" -u "src\pipeline.py" --force
) else (
    py -3 -u "src\pipeline.py" --force
)
set "EXIT_CODE=%ERRORLEVEL%"

if not "!EXIT_CODE!"=="0" (
    echo [ERROR] Pipeline encountered an error with exit code !EXIT_CODE!.
    pause
    exit /b !EXIT_CODE!
)

echo [SUCCESS] Full scan completed successfully.
pause
exit /b 0
