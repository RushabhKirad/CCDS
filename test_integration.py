#!/usr/bin/env python3
"""
Integration Test Script for Cognitive Cyber Defense System
Tests all modules and their integration points
"""

import requests
import time
import json
import sys
from datetime import datetime

def print_test_header(test_name):
    print(f"\n{'='*60}")
    print(f"TESTING: {test_name}")
    print(f"{'='*60}")

def test_module_health(name, port):
    """Test if a module's health endpoint is working"""
    try:
        response = requests.get(f"http://localhost:{port}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"[PASS] {name} - Health Check PASSED")
            print(f"   Status: {data.get('status', 'unknown')}")
            print(f"   Service: {data.get('service', 'unknown')}")
            return True
        else:
            print(f"[FAIL] {name} - Health Check FAILED (Status: {response.status_code})")
            return False
    except Exception as e:
        print(f"[FAIL] {name} - Health Check FAILED (Error: {str(e)})")
        return False

def test_main_backend():
    """Test main backend functionality"""
    print_test_header("MAIN BACKEND (Port 3000)")
    
    # Test user registration
    try:
        test_user = {
            "name": "Test User",
            "email": f"test_{int(time.time())}@gmail.com",
            "password": "TestPass123!"
        }
        
        response = requests.post("http://localhost:3000/api/register", 
                               json=test_user, timeout=5)
        
        if response.status_code == 201:
            print("[PASS] User Registration - PASSED")
            
            # Test login
            login_data = {
                "email": test_user["email"],
                "password": test_user["password"]
            }
            
            response = requests.post("http://localhost:3000/api/login", 
                                   json=login_data, timeout=5)
            
            if response.status_code == 200:
                result = response.json()
                print("[PASS] User Login - PASSED")
                print(f"   Token received: {bool(result.get('token'))}")
                return True
            else:
                print(f"[FAIL] User Login - FAILED (Status: {response.status_code})")
                return False
        else:
            print(f"[FAIL] User Registration - FAILED (Status: {response.status_code})")
            return False
            
    except Exception as e:
        print(f"[FAIL] Main Backend Test - FAILED (Error: {str(e)})")
        return False

def test_frontend_integration():
    """Test frontend integration"""
    print_test_header("FRONTEND INTEGRATION (Port 8080)")
    
    try:
        # Test if frontend is accessible
        response = requests.get("http://localhost:8080", timeout=5)
        if response.status_code == 200:
            print("[PASS] Frontend Access - PASSED")
            
            # Check if JavaScript module loading is configured
            content = response.text
            if "loadModule" in content and "moduleUrl" in content:
                print("[PASS] Module Loading Function - FOUND")
                
                # Check for all three modules
                modules_found = {
                    "anomaly": "localhost:8001" in content,
                    "email": "localhost:5001" in content, 
                    "insider": "localhost:5002" in content
                }
                
                for module, found in modules_found.items():
                    status = "[FOUND]" if found else "[MISSING]"
                    print(f"   {module.title()} Module Config: {status}")
                
                return all(modules_found.values())
            else:
                print("[FAIL] Module Loading Function - NOT FOUND")
                return False
        else:
            print(f"[FAIL] Frontend Access - FAILED (Status: {response.status_code})")
            return False
            
    except Exception as e:
        print(f"[FAIL] Frontend Test - FAILED (Error: {str(e)})")
        return False

def test_cross_module_integration():
    """Test cross-module integration via health checks"""
    print_test_header("CROSS-MODULE INTEGRATION")
    
    modules = [
        ("Email Security", 5001),
        ("Insider Threat", 5002), 
        ("Anomaly Detection", 8001)
    ]
    
    results = []
    for name, port in modules:
        result = test_module_health(name, port)
        results.append(result)
        
        if result:
            # Test if module can be accessed from frontend
            try:
                # Simulate frontend health check
                response = requests.get(f"http://localhost:{port}/health", timeout=2)
                if response.status_code == 200:
                    print(f"   Frontend Integration: [READY]")
                else:
                    print(f"   Frontend Integration: [NOT READY]")
            except:
                print(f"   Frontend Integration: [NOT ACCESSIBLE]")
    
    return all(results)

def run_comprehensive_test():
    """Run all integration tests"""
    print("COGNITIVE CYBER DEFENSE SYSTEM")
    print("COMPREHENSIVE INTEGRATION TEST")
    print(f"    Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    test_results = []
    
    # Test 1: Main Backend
    test_results.append(("Main Backend", test_main_backend()))
    
    # Test 2: Frontend Integration  
    test_results.append(("Frontend Integration", test_frontend_integration()))
    
    # Test 3: Cross-Module Integration
    test_results.append(("Cross-Module Integration", test_cross_module_integration()))
    
    # Test 4: Individual Module Health Checks
    print_test_header("INDIVIDUAL MODULE HEALTH CHECKS")
    modules = [
        ("Main Backend", 3000),
        ("Email Security", 5001),
        ("Insider Threat", 5002),
        ("Anomaly Detection", 8001),
        ("Frontend Server", 8080)
    ]
    
    module_results = []
    for name, port in modules:
        if port == 8080:  # Frontend doesn't have /health endpoint
            try:
                response = requests.get(f"http://localhost:{port}", timeout=5)
                result = response.status_code == 200
                status = "[RUNNING]" if result else "[NOT RUNNING]"
                print(f"{name} (Port {port}): {status}")
                module_results.append(result)
            except:
                print(f"{name} (Port {port}): [NOT RUNNING]")
                module_results.append(False)
        else:
            result = test_module_health(name, port)
            module_results.append(result)
    
    test_results.append(("Module Health Checks", all(module_results)))
    
    # Final Results
    print(f"\n{'='*60}")
    print("FINAL TEST RESULTS")
    print(f"{'='*60}")
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "[PASSED]" if result else "[FAILED]"
        print(f"{test_name:<25}: {status}")
        if result:
            passed += 1
    
    print(f"\nOVERALL RESULT: {passed}/{total} tests passed")
    
    if passed == total:
        print("ALL TESTS PASSED! System is ready for use.")
        print("\nACCESS POINTS:")
        print("   Main System:      http://localhost:8080")
        print("   Email Security:   http://localhost:5001")
        print("   Insider Threat:   http://localhost:5002") 
        print("   Anomaly Detection: http://localhost:8001")
        return True
    else:
        print(f"WARNING: {total - passed} test(s) failed. Please check the modules.")
        return False

if __name__ == "__main__":
    success = run_comprehensive_test()
    sys.exit(0 if success else 1)