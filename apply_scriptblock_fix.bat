@echo off
:: Automatically elevate to Administrator if not already running as admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ========================================================
echo  Cyber Mistake Detector - Hardening Fix Utility
echo  Enabling PowerShell Script Block Logging (Event ID 4104)
echo ========================================================
echo.

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

echo.
echo ========================================================
echo  Fix successfully applied! You can now rerun the scan.
echo ========================================================
echo.
pause
