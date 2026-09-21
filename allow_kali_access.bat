@echo off
:: BatchGotAdmin
:: Check for Administrator privileges
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

:: If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges to modify Windows Firewall...
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
    
    echo ===================================================
    echo      CIPHER - Temporary Kali Access Script
    echo ===================================================
    echo.
    echo Opening Port 5174 for the Vulnerable App...
    powershell -Command "New-NetFirewallRule -DisplayName 'CIPHER_TEMP_KALI' -Direction Inbound -LocalPort 5174 -Protocol TCP -Action Allow"
    
    echo.
    echo [SUCCESS] Port 5174 is now OPEN. 
    echo You can now access the Vulnerable App from your Kali VM!
    echo.
    echo ---------------------------------------------------
    echo IMPORTANT: Keep this window open while you test.
    echo When you are done, press any key below to close 
    echo the port and secure your computer again.
    echo ---------------------------------------------------
    echo.
    pause
    
    echo.
    echo Closing Port 5174...
    powershell -Command "Remove-NetFirewallRule -DisplayName 'CIPHER_TEMP_KALI'"
    
    echo.
    echo [SECURED] Port 5174 has been closed successfully.
    echo Press any key to exit.
    pause
