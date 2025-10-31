@echo off
echo Starting Frontend Server...
cd frontend\landing-page
python -m http.server 8080
pause