#!/usr/bin/env python3
"""
Simple Status Check for Cognitive Cyber Defense System
"""

import requests
import time

def check_module(name, port, endpoint="/health"):
    """Check if a module is running"""
    try:
        if endpoint == "/":
            response = requests.get(f"http://localhost:{port}", timeout=3)
        else:
            response = requests.get(f"http://localhost:{port}{endpoint}", timeout=3)
        
        if response.status_code == 200:
            print(f"[PASS] {name} (Port {port}) - RUNNING")
            return True
        else:
            print(f"[FAIL] {name} (Port {port}) - NOT RESPONDING")
            return False
    except:
        print(f"[FAIL] {name} (Port {port}) - NOT RUNNING")
        return False

def main():
    print("COGNITIVE CYBER DEFENSE SYSTEM - STATUS CHECK")
    print("=" * 50)
    
    modules = [
        ("Main Backend", 3000, "/health"),
        ("Email Security", 5001, "/health"), 
        ("Insider Threat", 5002, "/health"),
        ("Anomaly Detection", 8001, "/health"),
        ("Frontend Server", 8080, "/")
    ]
    
    results = []
    for name, port, endpoint in modules:
        result = check_module(name, port, endpoint)
        results.append(result)
    
    print("\n" + "=" * 50)
    running = sum(results)
    total = len(results)
    
    print(f"STATUS: {running}/{total} modules running")
    
    if running == total:
        print("SYSTEM STATUS: ALL MODULES READY")
        print("\nACCESS POINTS:")
        print("- Main System: http://localhost:8080")
        print("- Email Security: http://localhost:5001")
        print("- Insider Threat: http://localhost:5002")
        print("- Anomaly Detection: http://localhost:8001")
    else:
        print("SYSTEM STATUS: SOME MODULES NOT RUNNING")
        print("Please start all modules using: python run_all_modules.py")

if __name__ == "__main__":
    main()