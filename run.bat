@echo off
:: Check for Administrator privileges
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
    
    echo ==========================================
    echo Starting CIPHER Platform (Admin Mode)
    echo ==========================================
    echo.
    set "PROJECT_ROOT=%~dp0"
    
    echo [1/4] Opening Ports 5173 (Dashboard) and 5174 (Vulnerable App) for network access...
    powershell -Command "New-NetFirewallRule -DisplayName 'CIPHER_TEMP_DASHBOARD' -Direction Inbound -LocalPort 5173 -Protocol TCP -Action Allow"
    powershell -Command "New-NetFirewallRule -DisplayName 'CIPHER_TEMP_KALI' -Direction Inbound -LocalPort 5174 -Protocol TCP -Action Allow"
    
    echo [2/4] Launching Backend Terminal...
    start "CIPHER Backend" cmd /k "cd /d "%PROJECT_ROOT%backend" && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"
    
    echo Waiting for backend to initialize (5 seconds)...
    timeout /t 5 /nobreak >nul

    echo [3/4] Launching Frontend Terminal...
    start "CIPHER Frontend" cmd /c "cd /d "%PROJECT_ROOT%frontend" && npm run dev"

    echo [4/4] Launching Vulnerable App Terminal...
    start "CIPHER Vulnerable App" cmd /k "cd /d "%PROJECT_ROOT%vulnerable_app" && python -m uvicorn main:app --host 0.0.0.0 --port 5174 --reload"

    echo.
    echo ---------------------------------------------------
    echo All services running! Port 5174 is OPEN for Kali.
    echo.
    echo IMPORTANT: Keep this original window open while you test.
    echo When you are done, press any key below to close 
    echo the firewall port and secure your computer.
    echo ---------------------------------------------------
    pause
    
    echo Closing Ports...
    powershell -Command "Remove-NetFirewallRule -DisplayName 'CIPHER_TEMP_DASHBOARD' -ErrorAction SilentlyContinue"
    powershell -Command "Remove-NetFirewallRule -DisplayName 'CIPHER_TEMP_KALI' -ErrorAction SilentlyContinue"
    
    echo Closing CIPHER terminals...
    taskkill /FI "WindowTitle eq CIPHER Backend*" /T /F >nul 2>&1
    taskkill /FI "WindowTitle eq CIPHER Vulnerable App*" /T /F >nul 2>&1
    taskkill /IM node.exe /T /F >nul 2>&1
    
    echo [SECURED] Firewall port closed and terminals stopped.
    echo Press any key to exit.
    pause
