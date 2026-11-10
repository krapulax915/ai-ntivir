@echo off
setlocal enabledelayedexpansion
echo ========================================
echo  AI ANTIVIRUS MANUAL LAUNCHER v23.0
echo ========================================
echo.
echo Python kereses es ellenorzese...
set "FOUND_PYTHON="

REM Check primary Python path
if exist "C:\Program Files\Python310\pythonw.exe" (
    set "FOUND_PYTHON=C:\Program Files\Python310\pythonw.exe"
    echo ✓ Primary Python talalhato: C:\Program Files\Python310\pythonw.exe
    goto python_ok
)
if exist "C:\Program Files\Python310\pythonw.exe" (
    set "FOUND_PYTHON=C:\Program Files\Python310\pythonw.exe"
    echo ✓ Primary Python talalhato: C:\Program Files\Python310\pythonw.exe
    goto python_ok
)

REM Search for Python in common locations
echo ⚠ Primary Python nem talalhato, kereses mas helyeken...
if exist "C:\Program Files\Python310\pythonw.exe" (
    set "FOUND_PYTHON=C:\Program Files\Python310\pythonw.exe"
    echo ✓ Python talalhato: Program Files
    goto python_ok
)
if exist "C:\Program Files ^(x86^)\Python310\pythonw.exe" (
    set "FOUND_PYTHON=C:\Program Files ^(x86^)\Python310\pythonw.exe"
    echo ✓ Python talalhato: Program Files x86
    goto python_ok
)
if exist "%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe" (
    set "FOUND_PYTHON=%LOCALAPPDATA%\Programs\Python\Python310\pythonw.exe"
    echo ✓ Python talalhato: User Programs
    goto python_ok
)

REM Try PATH search
echo Kereses a PATH-ban...
for /f "tokens=*" %%i in ('where pythonw 2>nul') do (
    set "FOUND_PYTHON=%%i"
    echo ✓ Python talalhato PATH-ban: %%i
    goto python_ok
)

echo ❌ HIBA: Python nem talalhato
echo.
echo Lehetseges megoldasok:
echo 1. Telepitse a Python 3.10-et
echo 2. Futtassa ujra a telepitot
echo 3. Ellenorizze a Python telepiteset
echo.
pause
exit /b 1

:python_ok
echo.
echo AI Antivirus ellenorzese...
if exist "C:\Program Files\AI_Antivirus\main.py" (
    echo ✓ AI Antivirus talalhato: C:\Program Files\AI_Antivirus
) else (
    echo ❌ AI Antivirus nem talalhato: C:\Program Files\AI_Antivirus
    echo Kerem futtassa ujra a telepitot
    pause
    exit /b 1
)

echo AI Antivirus inditasa...
echo Python: %FOUND_PYTHON%
echo Konyvtar: C:\Program Files\AI_Antivirus
echo.
cd /d "C:\Program Files\AI_Antivirus"
start /min "" "%FOUND_PYTHON%" main.py

echo ✓ AI Antivirus inditas megkiserelt
echo Ellenorizze a rendszer tálcán vagy a Task Manager-ben.
echo.
echo Folyamat ellenorzese...
timeout /t 3 /nobreak >nul
tasklist /fi "imagename eq python*" | find /i "python" >nul
if %errorlevel% == 0 (
    echo ✓ Python folyamat fut - AI Antivirus valoszinuleg elindult
) else (
    echo ⚠ Python folyamat nem detektalva
)

timeout /t 5 /nobreak >nul
