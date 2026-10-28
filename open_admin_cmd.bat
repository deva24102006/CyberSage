@echo off
:: One-click launcher to open an Administrator Command Prompt
echo Requesting Administrator privileges...
powershell -Command "Start-Process cmd -Verb RunAs"
