@echo off
chcp 65001 >nul
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop-adsdk-agent.ps1"
echo.
pause
