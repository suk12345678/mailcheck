@echo off
title Mailcheck Anti-Spam Manager
cd /d "%~dp0"

:: Clean any orphaned background Outlook COM processes that may be hanging
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process -Filter \"Name = 'OUTLOOK.EXE'\" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*-Embedding*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"

:: Launch GUI in STA mode
start "" powershell.exe -ExecutionPolicy Bypass -NoProfile -STA -File "%~dp0mailcheck-gui.ps1"
