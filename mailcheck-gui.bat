@echo off
title Mailcheck Anti-Spam Manager
cd /d "%~dp0"
start "" powershell.exe -ExecutionPolicy Bypass -NoProfile -STA -File "%~dp0mailcheck-gui.ps1"
