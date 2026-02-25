@echo off
echo 🗄️ Starting Anomaly Detection Database API...
echo ===================================

cd dashboard
echo Starting Database API on http://localhost:5000
echo Dashboard will connect directly to database
echo.
python database_api.py

pause