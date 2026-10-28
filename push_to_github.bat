@echo off
setlocal
echo ====================================================
echo   CyberSage - Push to GitHub Repository
echo   Repo: https://github.com/deva24102006/CyberSage
echo ====================================================
echo.

set "PATH=C:\Users\LAB 02\AppData\Local\Microsoft\WinGet\Packages\Git.MinGit_Microsoft.Winget.Source_8wekyb3d8bbwe\cmd;C:\Users\LAB 02\AppData\Local\Microsoft\WinGet\Packages\GitHub.cli_Microsoft.Winget.Source_8wekyb3d8bbwe\bin;%PATH%"

echo Checking GitHub login...
gh auth status >nul 2>&1
if %errorlevel% neq 0 (
    echo You need to log in to GitHub once.
    echo Starting browser authentication...
    gh auth login --hostname github.com -p https -w
)

echo.
echo Pushing project to origin main...
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo ====================================================
    echo  [SUCCESS] Code successfully pushed to GitHub!
    echo  View repository: https://github.com/deva24102006/CyberSage
    echo ====================================================
) else (
    echo.
    echo If browser login was skipped, you can also push using a GitHub Token:
    echo git push https://YOUR_GITHUB_TOKEN@github.com/deva24102006/CyberSage.git main
)
echo.
pause
