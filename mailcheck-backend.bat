@echo off
title Mailcheck Rust Engine
setlocal enabledelayedexpansion
cd /d "%~dp0"

:: 1. Locate or build the executable
set "EXE=%~dp0target\release\mailcheck.exe"
if not exist "%EXE%" set "EXE=%~dp0target\debug\mailcheck.exe"

if not exist "%EXE%" (
    echo [INFO] Mailcheck binary not found. Building release binary with Cargo...
    where cargo >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Rust / Cargo is not installed or not in PATH.
        echo Please install Rust from https://rustup.rs/
        pause
        exit /b 1
    )
    cargo build --release
    set "EXE=%~dp0target\release\mailcheck.exe"
    if not exist "%EXE%" (
        echo [ERROR] Failed to compile mailcheck.
        pause
        exit /b 1
    )
)

:: 2. If command-line arguments are provided, pass them directly to the binary
if not "%~1"=="" (
    "%EXE%" %*
    exit /b %errorlevel%
)

:: 3. Interactive Menu when double-clicked without arguments
:MENU
cls
echo ============================================================
echo           Mailcheck - Rust Anti-Spam Backend Engine         
echo ============================================================
echo.
echo   [1] Scan Inbox - Safe Dry Run (Inspect without changing)
echo   [2] Scan Inbox - Move Spam to Junk Email
echo   [3] Scan Inbox - Permanently Delete Spam
echo   [4] Start Background Watcher (Continuously monitors inbox)
echo   [5] Authenticate with Microsoft Account (Browser Sign-in)
echo   [6] View Active Rules and Patterns
echo   [7] Run Engine Unit Tests (cargo test)
echo   [Q] Quit
echo.
echo ============================================================
set /p "CHOICE=Select an option [1-7, Q]: "

if /i "%CHOICE%"=="1" goto SCAN_DRYRUN
if /i "%CHOICE%"=="2" goto SCAN_JUNK
if /i "%CHOICE%"=="3" goto SCAN_DELETE
if /i "%CHOICE%"=="4" goto WATCH
if /i "%CHOICE%"=="5" goto AUTH
if /i "%CHOICE%"=="6" goto RULES
if /i "%CHOICE%"=="7" goto TESTS
if /i "%CHOICE%"=="Q" goto EXIT

echo Invalid option. Please select 1 through 7, or Q.
timeout /t 2 >nul
goto MENU

:SCAN_DRYRUN
cls
echo [Running Safe Dry-Run Scan...]
echo.
"%EXE%" scan --dry-run
echo.
pause
goto MENU

:SCAN_JUNK
cls
echo [Running Scan - Moving detected spam to Junk Email...]
echo.
"%EXE%" scan --action move-to-junk
echo.
pause
goto MENU

:SCAN_DELETE
cls
echo ============================================================
echo WARNING: This will PERMANENTLY DELETE detected spam emails!
echo ============================================================
set /p "CONFIRM=Are you sure you want to permanently delete? (y/N): "
if /i not "%CONFIRM%"=="y" goto MENU
echo.
echo [Running Scan - Permanently deleting detected spam...]
"%EXE%" scan --action delete
echo.
pause
goto MENU

:WATCH
cls
echo [Starting Background Watcher...]
echo Press Ctrl+C to stop watching at any time.
echo.
"%EXE%" watch
echo.
pause
goto MENU

:AUTH
cls
echo [Starting Microsoft OAuth Browser Sign-in...]
echo.
"%EXE%" auth
echo.
pause
goto MENU

:RULES
cls
echo [Active Loaded Rules]
echo.
"%EXE%" rules
echo.
pause
goto MENU

:TESTS
cls
echo [Running Unit Tests...]
echo.
cargo test
echo.
pause
goto MENU

:EXIT
exit /b 0
