@echo off
echo ============================================================
echo    COGNITIVE CYBER DEFENSE SYSTEM
echo    Starting All Modules (Python Dependencies Installed)
echo ============================================================

echo.
echo [1/5] Starting Main Backend...
start "Main Backend" start_backend_simple.bat
timeout /t 2 /nobreak >nul

echo [2/5] Starting Email Security...
start "Email Security" start_email_security.bat  
timeout /t 2 /nobreak >nul

echo [3/5] Starting Insider Threat...
start "Insider Threat" start_insider_threat.bat
timeout /t 2 /nobreak >nul

echo [4/5] Starting Anomaly Detection...
start "Anomaly Detection" start_anomaly_detection.bat
timeout /t 2 /nobreak >nul

echo [5/5] Starting Frontend...
start "Frontend Server" start_frontend.bat

echo.
echo ============================================================
echo All modules started in separate windows!
echo.
echo ACCESS POINTS:
echo   Main System:      http://localhost:8080
echo   Email Security:   http://localhost:5001
echo   Insider Threat:   http://localhost:5002
echo   Anomaly Detection: http://localhost:8001
echo   Backend API:      http://localhost:3000
echo.
echo Wait 30 seconds then run: python test_integration.py
echo ============================================================
pause