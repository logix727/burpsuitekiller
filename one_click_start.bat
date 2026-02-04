@echo off
title BurpKiller Pro - Security Workbench
color 0a

echo ===================================================
echo    BURPKILLER PRO - API SECURITY WORKBENCH
echo ===================================================
echo.

:: 1. Check Python
echo [+] Checking Python Environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0c
    echo [ERROR] Python is not found! 
    echo Please install Python 3.10+ from python.org and check "Add to PATH".
    pause
    exit /b
)

:: 2. Install Dependencies
echo [+] Installing/Updating Dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    color 0e
    echo [WARNING] Some dependencies might have failed. Attempting to run anyway...
    echo.
)

:: 3. Run Application
echo [+] Launching Application...
echo.
python main.py

if %errorlevel% neq 0 (
    color 0c
    echo.
    echo [CRITICAL] The application crashed. See error above.
    pause
)
