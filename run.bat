@echo off
echo ==========================================
echo Starting CIPHER Platform
echo ==========================================
echo.

set "PROJECT_ROOT=%~dp0"

echo [1/4] Launching Backend Terminal...
start "CIPHER Backend" cmd /k "cd /d "%PROJECT_ROOT%backend" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

echo [2/4] Launching Frontend Terminal...
start "CIPHER Frontend" cmd /k "cd /d "%PROJECT_ROOT%frontend" && npm run dev"

echo [3/4] Launching Vulnerable App Terminal...
start "CIPHER Vulnerable App" cmd /k "cd /d "%PROJECT_ROOT%vulnerable_app" && python -m uvicorn main:app --host 0.0.0.0 --port 5174 --reload"

echo [4/4] Launching Firewall Bypass Terminal...
start "CIPHER Firewall Bypass" cmd /c "cd /d "%PROJECT_ROOT%" && allow_kali_access.bat"

echo.
echo All services have been launched in their own terminal windows!
echo You can safely close this window.
pause
