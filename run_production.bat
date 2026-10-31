@echo off
title Cyber Mistake Detector - Production WSGI Server
cd /d "%~dp0"
echo ============================================================
echo  Cyber Mistake Detector - Production WSGI Server
echo ============================================================
echo  Starting multi-threaded production server (Waitress)...
echo  Local URL: http://127.0.0.1:5000/
echo  LAN URL  : http://0.0.0.0:5000/
echo  Press Ctrl+C in this window to stop the server.
echo ============================================================

:: Open web browser after 1 second
start "" "http://127.0.0.1:5000/"

:: Start production WSGI server
python wsgi.py
pause
