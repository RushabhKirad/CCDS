@echo off
echo ================================================================
echo      COGNITIVE CYBER DEFENSE SYSTEM - COMPLETE LAUNCHER
echo ================================================================
echo.

echo [1/6] Starting Landing Page (Port 8000)...
start "Landing Page" cmd /k "cd /d frontend\landing-page && python -m http.server 8000"
timeout /t 2 /nobreak >nul

echo [2/6] Starting Backend API (Port 3000)...
start "Backend API" cmd /k "cd /d backend && node server.js"
timeout /t 3 /nobreak >nul

echo [3/6] Starting PQC Service (Port 5005)...
start "PQC Service" cmd /k "cd /d backend\pqc-service && python pqc_service.py"
timeout /t 2 /nobreak >nul

echo [4/6] Starting Email Security / Phishing Detection (Port 5000)...
start "Email Security" cmd /k "cd /d EMAIL_SECURITY_SYSTEM_2 && python app.py"
timeout /t 3 /nobreak >nul

echo [5/6] Starting Insider Threat Detection (Port 5050)...
start "Insider Threat" cmd /k "cd /d Insider_threat_detection && python app.py"
timeout /t 3 /nobreak >nul

echo [6/6] Starting Anomaly Detection System...
start "Anomaly Detection" cmd /k "cd /d anomaly-detection && python run.py"

echo.
echo ================================================================
echo      ALL SERVICES STARTED SUCCESSFULLY!
echo ================================================================
echo.
echo   ACCESS POINTS:
echo   ---------------------------------------------------------------
echo   Landing Page:         http://localhost:8000
echo   Backend API:          http://localhost:3000
echo   PQC Service:          http://localhost:5005
echo   Email Security:       http://localhost:5000
echo   Insider Threat:       http://localhost:5050
echo   Anomaly ML Backend:   http://localhost:8080
echo   Anomaly Database API: http://localhost:5002
echo   Anomaly Dashboard:    http://localhost:3030
echo.
echo   Close individual command windows to stop each service.
echo ================================================================
pause
