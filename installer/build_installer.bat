@echo off
REM ============================================================
REM  AI-NTIVIR installer build script (Windows 10/11)
REM  1) PyInstaller: builds the AI-NTIVIR.exe application bundle
REM  2) Inno Setup:  builds AI-NTIVIR-Setup-1.0.0.exe
REM  3) Optional:    SignPath signing (if signpath_config.json exists)
REM ============================================================
setlocal
cd /d "%~dp0.."

echo ============================================
echo  1/3 PyInstaller build
echo ============================================
pyinstaller installer\AI-NTIVIR.spec --noconfirm --clean
if errorlevel 1 goto :error

echo ============================================
echo  2/3 Inno Setup
echo ============================================
set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist %ISCC% set ISCC="C:\Program Files\Inno Setup 6\ISCC.exe"
%ISCC% installer\AI-NTIVIR.iss
if errorlevel 1 goto :error

echo ============================================
echo  3/3 SignPath signing (optional)
echo ============================================
if exist installer\signpath_config.json (
    powershell -NoProfile -ExecutionPolicy Bypass -File installer\sign_with_signpath.ps1 -File "installer\output\AI-NTIVIR-Setup-1.0.0.exe"
) else (
    echo [SKIP] installer\signpath_config.json not found - installer stays UNSIGNED.
    echo        Copy signpath_config.template.json to signpath_config.json, fill it in,
    echo        then run: powershell -ExecutionPolicy Bypass -File installer\sign_with_signpath.ps1 -File "installer\output\AI-NTIVIR-Setup-1.0.0.exe"
)

echo.
echo BUILD OK: installer\output\AI-NTIVIR-Setup-1.0.0.exe
goto :eof

:error
echo BUILD FAILED (see output above)
exit /b 1
