@echo off
title CyberSage - Standalone Windows Security Auditor
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0audit_collector.ps1"
if %errorlevel% neq 0 (
    echo.
    echo [INFO] Audit complete.
    pause
)
