@echo off
title Cyber Mistake Detector
cd /d "%~dp0"
echo ============================================================
echo  Cyber Mistake Detector - Educational Security Auditor
echo ============================================================
echo  Starting local web server...
echo  Opening browser to: http://127.0.0.1:5000/
echo  Press Ctrl+C in this window to stop the application.
echo ============================================================

:: Open web browser after 1 second
start "" "http://127.0.0.1:5000/"

:: Start Flask app
python app.py
pause
