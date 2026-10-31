@echo off
:: ============================================================================
:: CIPHER launcher (Windows)
::  - Backend runs elevated (live packet capture needs it) but listens on 127.0.0.1 only.
::  - The deliberately vulnerable demo app runs WITHOUT admin rights.
::  - Nothing is exposed to the LAN unless you explicitly answer Y below.
:: ============================================================================

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges for packet capture...
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
    set "PROJECT_ROOT=%~dp0"

    echo ==========================================
    echo Starting CIPHER Platform
    echo ==========================================
    echo.
    echo Prevention mode defaults to detect_only. Set CIPHER_PREVENTION_MODE in backend\.env to change it.
    echo.

    set "VULN_HOST=127.0.0.1"
    set "EXPOSE_LAN=N"
    set /p EXPOSE_LAN="Expose the VULNERABLE demo app (port 5174) to your LAN for a Kali/Termux attacker? Use only on an isolated lab network. [y/N]: "
    if /I "%EXPOSE_LAN%"=="Y" (
        set "VULN_HOST=0.0.0.0"
        echo Opening inbound TCP 5174 for this session only...
        powershell -Command "New-NetFirewallRule -DisplayName 'CIPHER_TEMP_VULNAPP' -Direction Inbound -LocalPort 5174 -Protocol TCP -Action Allow" >nul
    )

    echo [1/3] Launching backend on 127.0.0.1:8000 ...
    start "CIPHER Backend" cmd /k "cd /d backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

    echo Waiting for backend to initialize (5 seconds)...
    timeout /t 5 /nobreak >nul

    echo [2/3] Launching dashboard on http://localhost:5173 ...
    start "CIPHER Frontend" cmd /k "cd /d frontend && npm run dev"

    echo [3/3] Launching vulnerable demo app WITHOUT admin rights on %VULN_HOST%:5174 ...
    echo @echo off > "%temp%\cipher_vuln.bat"
    echo cd /d "%PROJECT_ROOT%vulnerable_app" >> "%temp%\cipher_vuln.bat"
    echo call run.bat %VULN_HOST% >> "%temp%\cipher_vuln.bat"
    runas /trustlevel:0x20000 "cmd /k %temp%\cipher_vuln.bat"

    echo.
    echo ---------------------------------------------------
    echo All services started.
    echo Dashboard:      http://localhost:5173
    echo Vulnerable app: http://%VULN_HOST%:5174
    echo.
    echo Press any key here when you are done to stop CIPHER
    echo and remove the temporary firewall rule.
    echo ---------------------------------------------------
    pause

    powershell -Command "Remove-NetFirewallRule -DisplayName 'CIPHER_TEMP_VULNAPP' -ErrorAction SilentlyContinue"
    del "%temp%\cipher_vuln.bat" >nul 2>&1
    taskkill /FI "WindowTitle eq CIPHER Backend*" /T /F >nul 2>&1
    taskkill /FI "WindowTitle eq CIPHER Frontend*" /T /F >nul 2>&1
    taskkill /FI "WindowTitle eq CIPHER Vulnerable App*" /T /F >nul 2>&1

    echo [SECURED] Services stopped and temporary firewall rule removed.
    pause
