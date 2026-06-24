@echo off
setlocal enabledelayedexpansion
title cablecheck installer

echo.
echo  ================================================
echo   cablecheck installer
echo  ================================================
echo.

:: ── Check admin ──────────────────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Not running as Administrator.
    echo      Right-click install.bat and choose "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: ── Check if cablecheck.exe is present ───────────────────────────────────────
if not exist "%~dp0cablecheck.exe" (
    echo  [!] cablecheck.exe not found in this folder.
    echo      Make sure cablecheck.exe is in the same folder as this script.
    echo.
    pause
    exit /b 1
)

:: ── Check Npcap ───────────────────────────────────────────────────────────────
echo  [1/2] Checking for Npcap...

set NPCAP_FOUND=0

:: Check registry for Npcap installation
reg query "HKLM\SOFTWARE\Npcap" >nul 2>&1 && set NPCAP_FOUND=1
if !NPCAP_FOUND!==0 (
    reg query "HKLM\SOFTWARE\WOW6432Node\Npcap" >nul 2>&1 && set NPCAP_FOUND=1
)

:: Also check if the DLL is present
if !NPCAP_FOUND!==0 (
    if exist "C:\Windows\System32\Npcap\wpcap.dll" (set NPCAP_FOUND=1)
)

if !NPCAP_FOUND!==1 (
    echo       Npcap already installed. Skipping.
) else (
    echo       Npcap not found. Downloading...
    echo.

    :: Check if curl is available (Windows 10+)
    where curl >nul 2>&1
    if %errorlevel% neq 0 (
        echo  [!] curl not found. Please download and install Npcap manually:
        echo      https://npcap.com/dist/npcap-1.79.exe
        echo.
        pause
        exit /b 1
    )

    set NPCAP_URL=https://npcap.com/dist/npcap-1.79.exe
    set NPCAP_INSTALLER=%TEMP%\npcap_installer.exe

    echo       Downloading from npcap.com...
    curl -L --progress-bar -o "!NPCAP_INSTALLER!" "!NPCAP_URL!"

    if !errorlevel! neq 0 (
        echo.
        echo  [!] Download failed. Check your internet connection or install manually:
        echo      https://npcap.com/dist/npcap-1.79.exe
        echo.
        pause
        exit /b 1
    )

    echo.
    echo       Installing Npcap...
    echo       Follow the installer — default options are fine.
    echo.
    "!NPCAP_INSTALLER!" /winpcap_mode=yes

    if !errorlevel! neq 0 (
        echo.
        echo  [!] Npcap installation failed or was cancelled.
        echo      Please install manually: https://npcap.com/dist/npcap-1.79.exe
        echo.
        pause
        exit /b 1
    )

    echo.
    echo  [✓] Npcap installed.
)

:: ── Create desktop shortcut ──────────────────────────────────────────────────
echo.
echo  [2/2] Creating desktop shortcut...

set SCRIPT_DIR=%~dp0
set SHORTCUT=%USERPROFILE%\Desktop\cablecheck.lnk
set TARGET=%SCRIPT_DIR%cablecheck.exe

:: Use PowerShell to create shortcut with runas (admin) flag
powershell -NoProfile -Command ^
    "$ws = New-Object -ComObject WScript.Shell;" ^
    "$s = $ws.CreateShortcut('%SHORTCUT%');" ^
    "$s.TargetPath = '%TARGET%';" ^
    "$s.WorkingDirectory = '%SCRIPT_DIR%';" ^
    "$s.Description = 'cablecheck — dual-NIC loopback cable tester';" ^
    "$s.Save();" ^
    "$bytes = [System.IO.File]::ReadAllBytes('%SHORTCUT%');" ^
    "$bytes[0x15] = $bytes[0x15] -bor 0x20;" ^
    "[System.IO.File]::WriteAllBytes('%SHORTCUT%', $bytes);"

if exist "%SHORTCUT%" (
    echo  [✓] Shortcut created on Desktop.
) else (
    echo  [!] Shortcut creation failed — you can still run cablecheck.exe directly.
)

:: ── Done ─────────────────────────────────────────────────────────────────────
echo.
echo  ================================================
echo   Installation complete.
echo.
echo   cablecheck.exe is ready to use.
echo   Launch from the Desktop shortcut — it will
echo   prompt for admin automatically.
echo  ================================================
echo.
pause
