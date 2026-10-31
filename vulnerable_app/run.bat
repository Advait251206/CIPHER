@echo off
title CIPHER Vulnerable App
cd /d "%~dp0"
set "HOST=%~1"
if "%HOST%"=="" set "HOST=127.0.0.1"
if exist "..\backend\.venv\Scripts\python.exe" (
    ..\backend\.venv\Scripts\python.exe -m uvicorn main:app --host %HOST% --port 5174
) else (
    python -m uvicorn main:app --host %HOST% --port 5174
)
