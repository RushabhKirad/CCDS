@echo off
echo ============================================================
echo    COGNITIVE CYBER DEFENSE SYSTEM
echo    Starting All Modules...
echo ============================================================

echo.
echo Starting modules in separate windows...
echo.

start "Main Backend" start_backend.bat
timeout /t 3 /nobreak >nul

start "Email Security" start_email_security.bat  
timeout /t 3 /nobreak >nul

start "Insider Threat" start_insider_threat.bat
timeout /t 3 /nobreak >nul

start "Anomaly Detection" start_anomaly_detection.bat
timeout /t 3 /nobreak >nul

start "Frontend Server" start_frontend.bat

echo.
echo ============================================================
echo All modules are starting in separate windows...
echo.
echo ACCESS POINTS:
echo   Main System:      http://localhost:8080
echo   Email Security:   http://localhost:5001
echo   Insider Threat:   http://localhost:5002
echo   Anomaly Detection: http://localhost:8001
echo   Backend API:      http://localhost:3000
echo.
echo Close individual windows to stop modules
echo ============================================================
pause