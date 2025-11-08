#!/usr/bin/env python3
"""
Complete System Runner - One file to run everything
Handles database setup, system initialization, and app startup
"""

import os
import sys
import subprocess
import mysql.connector
from mysql.connector import Error
import time
import webbrowser
from threading import Timer

def print_banner():
    print("=" * 60)
    print("INSIDER THREAT DETECTION SYSTEM")
    print("=" * 60)
    print("Complete System Startup")
    print("Dashboard: http://localhost:5000")
    print("Login: admin / admin123")
    print("=" * 60)

def check_mysql_connection():
    """Check if MySQL is running and accessible"""
    print("[CHECK] Checking MySQL connection...")
    
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='samarth@2904'
        )
        
        if connection.is_connected():
            print("[PASS] MySQL connection successful")
            connection.close()
            return True
        else:
            print("[FAIL] MySQL connection failed")
            return False
            
    except Error as e:
        print(f"[FAIL] MySQL error: {e}")
        print("[INFO] Make sure MySQL is installed and running")
        print("[INFO] Check if password 'samarth@2904' is correct")
        return False

def setup_database():
    """Setup database using SQL file"""
    print("[SETUP] Setting up database...")
    
    try:
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='samarth@2904'
        )
        
        cursor = connection.cursor()
        
        # Read and execute SQL file
        sql_file = os.path.join(os.getcwd(), 'CLEAN_DATABASE.sql')
        
        if not os.path.exists(sql_file):
            print("❌ CLEAN_DATABASE.sql not found")
            return False
        
        with open(sql_file, 'r', encoding='utf-8') as file:
            sql_script = file.read()
        
        # Split and execute SQL statements
        statements = sql_script.split(';')
        
        for statement in statements:
            statement = statement.strip()
            if statement:
                cursor.execute(statement)
        
        connection.commit()
        print("[PASS] Database setup completed")
        
        cursor.close()
        connection.close()
        return True
        
    except Error as e:
        print(f"[FAIL] Database setup failed: {e}")
        return False

def install_dependencies():
    """Install required Python packages"""
    print("[INSTALL] Installing dependencies...")
    
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements_new.txt'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print("[PASS] Dependencies installed")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"[FAIL] Failed to install dependencies: {e}")
        return False

def setup_system():
    """Initialize system with proper password hashing"""
    print("[INIT] Initializing system...")
    
    try:
        from werkzeug.security import generate_password_hash
        
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='samarth@2904',
            database='InsiderThreatDB'
        )
        
        cursor = connection.cursor()
        
        # Update admin password with proper hash
        admin_password_hash = generate_password_hash('admin123')
        
        cursor.execute("""
            UPDATE users 
            SET password_hash = %s 
            WHERE username = 'admin'
        """, (admin_password_hash,))
        
        connection.commit()
        print("[PASS] System initialized")
        
        cursor.close()
        connection.close()
        return True
        
    except Exception as e:
        print(f"[FAIL] System initialization failed: {e}")
        return False

def open_browser():
    """Open browser after delay"""
    time.sleep(3)
    try:
        webbrowser.open('http://localhost:5000')
        print("[INFO] Browser opened automatically")
    except:
        print("[INFO] Please open http://localhost:5000 manually")

def start_flask_app():
    """Start the Flask application"""
    print("[START] Starting Insider Threat Detection System...")
    print("[INFO] Dashboard will be available at: http://localhost:5000")
    print("[INFO] Login with: admin / admin123")
    print("[INFO] Admin Panel: Click 'Admin Panel' after login")
    print("\n[FEATURES] System Features:")
    print("   - USB Device Detection")
    print("   - File Access Control")
    print("   - AI Behavioral Learning")
    print("   - Real-time Monitoring")
    print("   - Admin Panel for File Restrictions")
    print("   - Performance Metrics Dashboard")
    print("\n[INFO] Press Ctrl+C to stop the system")
    print("=" * 60)
    
    # Open browser in background
    Timer(3.0, open_browser).start()
    
    # Start Flask app
    try:
        import app
        app.app.run(debug=False, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n[STOP] System stopped by user")
    except Exception as e:
        print(f"[FAIL] Flask app error: {e}")

def main():
    """Main execution function"""
    print_banner()
    
    # Step 1: Check MySQL
    if not check_mysql_connection():
        print("\n[FAIL] Cannot proceed without MySQL connection")
        print("[INFO] Please install MySQL and ensure it's running")
        input("Press Enter to exit...")
        return
    
    # Step 2: Install dependencies
    if not install_dependencies():
        print("\n[FAIL] Cannot proceed without required packages")
        input("Press Enter to exit...")
        return
    
    # Step 3: Setup database
    if not setup_database():
        print("\n[FAIL] Database setup failed")
        input("Press Enter to exit...")
        return
    
    # Step 4: Initialize system
    if not setup_system():
        print("\n[FAIL] System initialization failed")
        input("Press Enter to exit...")
        return
    
    print("\n[SUCCESS] System setup completed successfully!")
    print("[START] Starting web application...")
    time.sleep(2)
    
    # Step 5: Start Flask app
    start_flask_app()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[STOP] Setup interrupted by user")
    except Exception as e:
        print(f"\n[FAIL] Unexpected error: {e}")
        input("Press Enter to exit...")