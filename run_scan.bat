@echo off
:: MCP-APP One-Click Scanner – FINAL & BULLETPROOF
setlocal

set /p TARGET=Enter target (e.g., https://scanme.nmap.org): 
if "%TARGET%"=="" (
    echo [ERROR] No target entered!
    pause
    exit /b 1
)

echo.
echo [1/4] Starting backend...
start "" "backend\start_backend.bat"

timeout /t 7 >nul

echo [2/4] Starting scan on %TARGET%...
curl -s -X POST "http://127.0.0.1:8000/start_scan" ^
     -H "Content-Type: application/json" ^
     -d "{\"target\":\"%TARGET%\",\"tools\":[\"nmap\",\"subfinder\"]}" > temp.json

type temp.json

:: === EXTRACT FULL 36-CHAR UUID USING PYTHON (100% RELIABLE) ===
for /f "delims=" %%i in ('python -c "import json,sys; data=json.load(open('temp.json')); print(data['scan_id'])"') do set "SCAN_ID=%%i"

if not defined SCAN_ID (
    echo [ERROR] Failed to extract scan_id
    pause
    exit /b 1
)

echo Scan ID: %SCAN_ID% (36 chars)

echo [3/4] Waiting for scan to finish...
:wait
timeout /t 5 >nul
curl -s "http://127.0.0.1:8000/status/%SCAN_ID%" | findstr /C:"finished" >nul
if errorlevel 1 (
    echo   Still running... (check backend\backend.log)
    goto wait
)

echo [4/4] Scan finished!
start "" "http://127.0.0.1:8000/report/%SCAN_ID%"
start "" "http://127.0.0.1:8000/report_pdf/%SCAN_ID%"

echo.
echo Report : http://127.0.0.1:8000/report/%SCAN_ID%
echo PDF    : http://127.0.0.1:8000/report_pdf/%SCAN_ID%
echo LOG    : backend\backend.log
echo.
del temp.json
pause