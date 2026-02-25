#!/usr/bin/env python3
"""
🚀 Anomaly Detection System - One-Click Launcher
Starts all components: Backend, Database API, and Dashboard
"""

import subprocess
import time
import webbrowser
import os
import sys
from pathlib import Path
import threading
import requests

def run_service_in_background(command, cwd=None):
    """Run service in background without opening new window"""
    if cwd is None:
        cwd = os.getcwd()
    
    return subprocess.Popen(
        command,
        shell=True,
        cwd=cwd
    )

def main():
    print("🛡️ Anomaly Detection System - Starting All Services")
    print("=" * 60)
    
    # Get project root directory
    project_root = Path(__file__).parent
    backend_dir = project_root / "backend"
    dashboard_dir = project_root / "dashboard"
    
    # Check if directories exist
    if not backend_dir.exists():
        print("❌ Backend directory not found!")
        return
    
    if not dashboard_dir.exists():
        print("❌ Dashboard directory not found!")
        return
    
    print("🚀 Starting services in background...")
    
    processes = []
    
    # 1. Start Backend (ML Detection Engine)
    print("1️⃣ Starting ML Backend on port 8080...")
    backend_cmd = "python -m uvicorn app.main_ml:app --host 127.0.0.1 --port 8080"
    backend_process = run_service_in_background(backend_cmd, str(backend_dir))
    processes.append(backend_process)
    time.sleep(2)
    
    # 2. Start Database API
    print("2️⃣ Starting Database API on port 5002...")
    db_api_cmd = "python database_api.py"
    db_process = run_service_in_background(db_api_cmd, str(dashboard_dir))
    processes.append(db_process)
    time.sleep(2)
    
    # 3. Start Dashboard Server
    print("3️⃣ Starting Dashboard Server on port 3030...")
    dashboard_cmd = "python dashboard_server.py"
    dashboard_process = run_service_in_background(dashboard_cmd, str(dashboard_dir))
    processes.append(dashboard_process)
    time.sleep(5)
    
    # 4. Check if services are running
    print("4️⃣ Checking services...")
    try:
        response = requests.get("http://localhost:3030", timeout=2)
        print("✅ Dashboard server is running")
        webbrowser.open("http://localhost:3030")
    except:
        print("❌ Dashboard server not responding")
        print("   Try running manually: cd dashboard && python dashboard_server.py")
    time.sleep(1)

    # Keep main script running
    try:
        print("\n⏳ Press Ctrl+C to stop all services...")
        print("\n🌐 Services Running:")
        print("   🤖 ML Backend: http://localhost:8080")
        print("   🗄️ Database API: http://localhost:5002")
        print("   📊 Dashboard: http://localhost:3030")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down services...")
        for process in processes:
            try:
                process.terminate()
            except:
                pass
        print("   All services stopped.")

if __name__ == "__main__":
    main()