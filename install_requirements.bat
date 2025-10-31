@echo off
echo ============================================================
echo    COGNITIVE CYBER DEFENSE SYSTEM
echo    Installing All Required Dependencies
echo ============================================================

echo.
echo [1/4] Installing Email Security Requirements...
cd EMAIL_SECURITY_SYSTEM_2
pip install -r requirements.txt
cd ..

echo.
echo [2/4] Installing Insider Threat Requirements...
cd Insider_threat_detection
pip install -r requirements_new.txt
cd ..

echo.
echo [3/4] Installing Anomaly Detection Requirements...
cd nitedu-anomaly-detection
pip install -r requirements.txt
cd ..

echo.
echo [4/4] Installing Backend Requirements...
cd backend
npm install
cd ..

echo.
echo ============================================================
echo All dependencies installed successfully!
echo Now run START_ALL.bat to start all modules
echo ============================================================
pause