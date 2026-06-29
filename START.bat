@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo ================================================================
echo      COGNITIVE CYBER DEFENSE SYSTEM - COMPLETE LAUNCHER
echo ================================================================
echo.

REM ── Port assignments ─────────────────────────────────────────────
REM   Landing Page         : 8000
REM   Backend API (Node)   : 3000
REM   PQC Service          : 5005
REM   Email Security       : 6050
REM   Insider Threat SIEM  : 5050
REM   Anomaly Detection IDS: 5003
REM ─────────────────────────────────────────────────────────────────

echo [1/6] Starting Landing Page (Port 8000)...
if not exist "frontend\landing-page\index.html" (
    echo [WARN] frontend\landing-page\index.html not found - skipping
) else (
    start "Landing Page" cmd /k "cd /d "%~dp0frontend\landing-page" && python -m http.server 8000"
)
timeout /t 2 /nobreak >nul

echo [2/6] Starting Backend API (Port 3000)...
if not exist "backend\server.js" (
    echo [WARN] backend\server.js not found - skipping
) else (
    start "Backend API" cmd /k "cd /d "%~dp0backend" && node server.js"
)
timeout /t 3 /nobreak >nul

echo [3/6] Starting PQC Service (Port 5005)...
if not exist "backend\pqc-service\pqc_service.py" (
    echo [WARN] backend\pqc-service\pqc_service.py not found - skipping
) else (
    start "PQC Service" cmd /k "cd /d "%~dp0backend\pqc-service" && python pqc_service.py"
)
timeout /t 2 /nobreak >nul

echo [4/6] Starting Email Security / Phishing Detection (Port 6050)...
if not exist "%~dp0EMAIL_SECURITY_SYSTEM_2\run.py" (
    echo [WARN] EMAIL_SECURITY_SYSTEM_2\run.py not found - skipping
) else (
    start "Email Security" cmd /k "cd /d "%~dp0EMAIL_SECURITY_SYSTEM_2" && python run.py"
)
timeout /t 4 /nobreak >nul

echo [5/6] Starting Insider Threat Detection - Aegis SIEM (Port 5050)...
if not exist "Insider_main\app\main.py" (
    echo [WARN] Insider_main\app\main.py not found - skipping
) else (
    start "Insider Threat SIEM" cmd /k "cd /d "%~dp0Insider_main" && python -m uvicorn app.main:app --host 127.0.0.1 --port 5050 --reload"
)
timeout /t 4 /nobreak >nul

echo [6/6] Starting Anomaly Detection IDS Dashboard (Port 5003)...
if not exist "Anomaly_Detection_CICIDS-main\dashboard_app\app.py" (
    echo [WARN] Anomaly_Detection_CICIDS-main\dashboard_app\app.py not found - skipping
) else (
    start "Anomaly Detection IDS" cmd /k "cd /d "%~dp0Anomaly_Detection_CICIDS-main\dashboard_app" && python app.py"
)
timeout /t 5 /nobreak >nul

echo.
echo ================================================================
echo      ALL SERVICES STARTED SUCCESSFULLY!
echo ================================================================
echo.
echo   ACCESS POINTS:
echo   ---------------------------------------------------------------
echo   Landing Page          : http://localhost:8000
echo   Backend API (Node)    : http://localhost:3000
echo   PQC Service           : http://localhost:5005
echo   Email Security          : http://localhost:6050
echo   Insider Threat SIEM   : http://localhost:5050
echo   Anomaly Detection IDS : http://localhost:5003
echo   ---------------------------------------------------------------
echo.
echo   Opening Landing Page in browser...
timeout /t 2 /nobreak >nul
start "" "http://localhost:8000"
echo.
echo   Close individual command windows to stop each service.
echo ================================================================
echo.
pause
