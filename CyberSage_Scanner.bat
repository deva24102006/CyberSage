@echo off
title CyberSage - Enterprise Windows Security Auditor
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0audit_collector.ps1"
if %errorlevel% neq 0 (
    echo.
    echo [INFO] Auditor finished.
    pause
)
