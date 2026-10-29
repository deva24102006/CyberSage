@echo off
:: Automatically elevate to Administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges to run DISM...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

title CyberSage - Disable SMBv1 Protocol (Administrator)
echo ========================================================
echo  CyberSage - Disabling Legacy SMBv1 Protocol
echo  Fixing WannaCry / EternalBlue (MS17-010) Exposure
echo  Running with FULL Administrator Privileges
echo ========================================================
echo.

dism /online /disable-feature /featurename:SMB1Protocol /norestart

echo.
if %errorLevel% equ 0 (
    echo ========================================================
    echo  [SUCCESS] SMBv1 Protocol has been successfully DISABLED!
    echo  Error 740 was bypassed using Administrator elevation.
    echo ========================================================
) else (
    echo [ERROR] DISM encountered error code %errorLevel%.
)
echo.
pause
