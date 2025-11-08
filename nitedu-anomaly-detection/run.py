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

def run_command_in_new_window(command, title, cwd=None):
    """Run command in new CMD window"""
    if cwd is None:
        cwd = os.getcwd()
    
    cmd = f'start "{title}" cmd /k "cd /d {cwd} && {command}"'
    subprocess.Popen(cmd, shell=True)

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
    
    print("🚀 Starting services...")
    
    # 1. Start Backend (ML Detection Engine)
    print("1️⃣ Starting ML Backend on port 8080...")
    backend_cmd = "python -m uvicorn app.main_ml:app --reload --host 127.0.0.1 --port 8080"
    run_command_in_new_window(backend_cmd, "🤖 ML Backend (Port 8080)", str(backend_dir))
    time.sleep(2)
    
    # 2. Start Database API
    print("2️⃣ Starting Database API on port 5000...")
    db_api_cmd = "python database_api.py"
    run_command_in_new_window(db_api_cmd, "🗄️ Database API (Port 5000)", str(dashboard_dir))
    time.sleep(2)
    
    # 3. Open Dashboard in browser
    print("3️⃣ Opening Dashboard in browser...")
    dashboard_path = dashboard_dir / "live_dashboard_fixed.html"
    webbrowser.open(f"file:///{dashboard_path.absolute()}")
    time.sleep(1)
    
    # 4. Open Attack Tester
    print("4️⃣ Opening Attack Tester...")
    attack_tester_path = project_root / "attack_tester.html"
    if attack_tester_path.exists():
        webbrowser.open(f"file:///{attack_tester_path.absolute()}")
    
    print("\n✅ All services started successfully!")
    print("=" * 60)
    print("🌐 Services Running:")
    print("   • ML Backend:     http://localhost:8080")
    print("   • Database API:   http://localhost:5000") 
    print("   • Dashboard:      Opened in browser")
    print("   • Attack Tester:  Opened in browser")
    print("\n🔧 Manual Commands:")
    print("   • Test API:       curl http://localhost:8080/health")
    print("   • View Stats:     curl http://localhost:8080/api/v1/status")
    print("   • Test Attack:    Use Attack Tester in browser")
    print("\n⚠️  Keep all CMD windows open to maintain services")
    print("   Close this window when done testing")
    
    # Keep main script running
    try:
        print("\n⏳ Press Ctrl+C to stop all services...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down services...")
        print("   Close all CMD windows manually")

if __name__ == "__main__":
    main()