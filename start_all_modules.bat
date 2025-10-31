@echo off
echo ========================================
echo  Cognitive Cyber Defense System
echo  Starting All Modules...
echo ========================================

echo.
echo [1/5] Starting Main Backend Server (Port 3000)...
start "Main Backend" cmd /k "cd /d backend && npm install && node server.js"
timeout /t 3

echo.
echo [2/5] Starting Email Security System (Port 5001)...
start "Email Security" cmd /k "cd /d EMAIL_SECURITY_SYSTEM_2 && python -m pip install -r requirements.txt && set FLASK_APP=app.py && set FLASK_ENV=development && python -m flask run --port=5001"
timeout /t 3

echo.
echo [3/5] Starting Insider Threat Detection (Port 5002)...
start "Insider Threat" cmd /k "cd /d Insider_threat_detection && python -m pip install -r requirements_new.txt && python app.py --port=5002"
timeout /t 3

echo.
echo [4/5] Starting Anomaly Detection System (Port 8001)...
start "Anomaly Detection" cmd /k "cd /d nitedu-anomaly-detection && python -m pip install -r requirements.txt && python -m uvicorn backend.app.main_production:app --host 0.0.0.0 --port 8001"
timeout /t 3

echo.
echo [5/5] Starting Frontend Landing Page...
start "Frontend" cmd /k "cd /d frontend\landing-page && python -m http.server 8080"

echo.
echo ========================================
echo  All modules are starting...
echo  Please wait for all services to load
echo ========================================
echo.
echo  Access Points:
echo  - Main System: http://localhost:8080
echo  - Email Security: http://localhost:5001
echo  - Insider Threat: http://localhost:5002
echo  - Anomaly Detection: http://localhost:8001
echo  - Backend API: http://localhost:3000
echo.
echo  Press any key to close this window...
pause