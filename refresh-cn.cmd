@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\refresh-cn-feedback.ps1"
echo.
pause
