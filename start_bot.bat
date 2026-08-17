@echo off
title CigilBot
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [Error] .venv not found - run the setup steps from README/CLAUDE.md first.
    pause
    exit /b 1
)

echo Starting CigilBot... Close this window or press Ctrl+C to stop it.
echo.

.venv\Scripts\python.exe run.py

echo.
echo CigilBot stopped.
pause
