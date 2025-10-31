@echo off
echo Starting Anomaly Detection System...
cd nitedu-anomaly-detection
python -m uvicorn backend.app.main_production:app --host 0.0.0.0 --port 8001
pause