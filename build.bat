@echo off
setlocal enabledelayedexpansion
title cablecheck build pipeline
cd /d "%~dp0"

echo.
echo  ============================================================
echo   cablecheck build pipeline
echo   Builds exe + Inno Setup installer
echo  ============================================================
echo.

:: ── Check admin ──────────────────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Run this script as Administrator.
    pause & exit /b 1
)

:: ── Check icon exists ─────────────────────────────────────────────────────────
if not exist "%~dp0cablecheck.ico" (
    echo  [!] cablecheck.ico not found.
    echo      Download it from the GitHub repo and place it here:
    echo      %~dp0cablecheck.ico
    pause & exit /b 1
)

:: ── Step 1: pip dependencies ──────────────────────────────────────────────────
echo  [1/4] Installing Python dependencies...
pip install scapy psutil pyinstaller --quiet
if %errorlevel% neq 0 (
    echo  [!] pip failed. Make sure Python 3.10+ is installed and in PATH.
    pause & exit /b 1
)
echo       Done.
echo.

:: ── Step 2: PyInstaller — build exe ──────────────────────────────────────────
echo  [2/4] Building cablecheck.exe with PyInstaller...
if exist "%~dp0build_tmp" rmdir /s /q "%~dp0build_tmp"

pyinstaller ^
    --onefile ^
    --noconsole ^
    --uac-admin ^
    --name cablecheck ^
    --icon "%~dp0cablecheck.ico" ^
    --distpath "%~dp0install" ^
    --workpath "%~dp0build_tmp" ^
    --specpath "%~dp0build_tmp" ^
    "%~dp0cablecheck_gui.py"

if %errorlevel% neq 0 (
    echo  [!] PyInstaller failed — check output above.
    pause & exit /b 1
)

:: Copy install.bat into the install folder
copy /Y "%~dp0install.bat" "%~dp0install\install.bat" >nul

:: Clean PyInstaller temp
rmdir /s /q "%~dp0build_tmp" 2>nul
echo       Done — install\cablecheck.exe ready.
echo.

:: ── Step 3: Check for Npcap installer (needed for Inno to bundle it) ─────────
echo  [3/4] Checking for bundled Npcap installer...
if not exist "%~dp0npcap-1.79.exe" (
    echo       npcap-1.79.exe not found — downloading...
    curl -L --progress-bar -o "%~dp0npcap-1.79.exe" "https://npcap.com/dist/npcap-1.79.exe"
    if !errorlevel! neq 0 (
        echo  [!] Download failed. Get it manually from https://npcap.com and place
        echo      it at: %~dp0npcap-1.79.exe
        echo      Then re-run build.bat to finish building the installer.
        pause & exit /b 1
    )
) else (
    echo       npcap-1.79.exe already present. Skipping download.
)
echo.

:: ── Step 4: Inno Setup — build installer ─────────────────────────────────────
echo  [4/4] Building installer with Inno Setup...

:: Check common Inno Setup install locations
set ISCC=""
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)
if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
    set ISCC="C:\Program Files\Inno Setup 6\ISCC.exe"
)

if %ISCC%=="" (
    echo  [!] Inno Setup 6 not found.
    echo      Download and install it from: https://jrsoftware.org/isdl.php
    echo      Then re-run build.bat.
    echo.
    echo      The exe is still ready at: install\cablecheck.exe
    pause & exit /b 1
)

if not exist "%~dp0installer_output" mkdir "%~dp0installer_output"
%ISCC% "%~dp0cablecheck.iss"

if %errorlevel% neq 0 (
    echo  [!] Inno Setup failed — check output above.
    pause & exit /b 1
)

echo.
echo  ============================================================
echo   Build complete.
echo.
echo   Exe only (no Python needed):
echo     install\cablecheck.exe + install\install.bat
echo.
echo   Full installer (recommended for distribution):
echo     installer_output\cablecheck_setup.exe
echo.
echo   Upload cablecheck_setup.exe to GitHub Releases.
echo  ============================================================
echo.
pause
