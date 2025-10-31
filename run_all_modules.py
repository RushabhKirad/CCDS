#!/usr/bin/env python3
"""
Cognitive Cyber Defense System - Unified Module Launcher
Starts all modules with proper configuration and health checks
"""

import subprocess
import time
import os
import sys
import requests
from threading import Thread

def print_banner():
    print("=" * 60)
    print("    COGNITIVE CYBER DEFENSE SYSTEM")
    print("     Multi-Module Security Platform")
    print("=" * 60)

def check_port(port):
    """Check if a port is available"""
    try:
        response = requests.get(f"http://localhost:{port}/health", timeout=2)
        return response.status_code == 200
    except:
        return False

def start_module(name, command, port, cwd=None):
    """Start a module in a separate process"""
    print(f"[{name}] Starting on port {port}...")
    
    if cwd:
        full_cwd = os.path.join(os.getcwd(), cwd)
    else:
        full_cwd = os.getcwd()
    
    try:
        if sys.platform == "win32":
            # Windows
            subprocess.Popen(command, shell=True, cwd=full_cwd, 
                           creationflags=subprocess.CREATE_NEW_CONSOLE)
        else:
            # Linux/Mac
            subprocess.Popen(command, shell=True, cwd=full_cwd)
        
        # Wait a bit for the service to start
        time.sleep(3)
        
        # Check if service is running
        max_retries = 10
        for i in range(max_retries):
            if check_port(port):
                print(f"[{name}] [OK] Running on http://localhost:{port}")
                return True
            time.sleep(2)
        
        print(f"[{name}] [WARN] Started but health check failed")
        return False
        
    except Exception as e:
        print(f"[{name}] [FAIL] Failed to start: {e}")
        return False

def main():
    print_banner()
    
    # Check if we're in the right directory
    if not os.path.exists("EMAIL_SECURITY_SYSTEM_2"):
        print("[ERROR] Please run this script from the Cognitive-Cyber-Defense-System root directory")
        sys.exit(1)
    
    modules = [
        {
            "name": "Main Backend",
            "command": "npm install && node server.js",
            "port": 3000,
            "cwd": "backend"
        },
        {
            "name": "Email Security",
            "command": "python -m pip install -r requirements.txt && python app.py",
            "port": 5001,
            "cwd": "EMAIL_SECURITY_SYSTEM_2"
        },
        {
            "name": "Insider Threat",
            "command": "python -m pip install -r requirements_new.txt && python app.py --port=5002",
            "port": 5002,
            "cwd": "Insider_threat_detection"
        },
        {
            "name": "Anomaly Detection",
            "command": "python -m pip install -r requirements.txt && python -m uvicorn backend.app.main_production:app --host 0.0.0.0 --port 8001",
            "port": 8001,
            "cwd": "nitedu-anomaly-detection"
        },
        {
            "name": "Frontend Server",
            "command": "python -m http.server 8080",
            "port": 8080,
            "cwd": "frontend/landing-page"
        }
    ]
    
    print("\nStarting all modules...\n")
    
    started_modules = []
    
    for module in modules:
        success = start_module(
            module["name"], 
            module["command"], 
            module["port"], 
            module.get("cwd")
        )
        
        if success:
            started_modules.append(module)
        
        time.sleep(2)  # Wait between starts
    
    print("\n" + "=" * 60)
    print("MODULE STATUS SUMMARY")
    print("=" * 60)
    
    for module in started_modules:
        print(f"[OK] {module['name']:<20} http://localhost:{module['port']}")
    
    if len(started_modules) < len(modules):
        failed = len(modules) - len(started_modules)
        print(f"\n[WARN] {failed} module(s) failed to start properly")
    
    print("\nACCESS POINTS:")
    print("   Main System:      http://localhost:8080")
    print("   Email Security:   http://localhost:5001")
    print("   Insider Threat:   http://localhost:5002")
    print("   Anomaly Detection: http://localhost:8001")
    print("   Backend API:      http://localhost:3000")
    
    print("\nNEXT STEPS:")
    print("   1. Ensure MySQL database 'cyber_defense_db' exists")
    print("   2. Access the main system at http://localhost:8080")
    print("   3. Login and explore the integrated modules")
    
    print("\nAll modules are running in background processes")
    print("   Close terminal windows to stop individual modules")
    
    # Keep the script running to monitor
    try:
        while True:
            time.sleep(30)
            # Check if modules are still running
            running_count = sum(1 for module in started_modules if check_port(module["port"]))
            if running_count < len(started_modules):
                print(f"\n[WARN] Warning: {len(started_modules) - running_count} module(s) stopped running")
            time.sleep(30)
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped. Modules continue running in background.")

if __name__ == "__main__":
    main()