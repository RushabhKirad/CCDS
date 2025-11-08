#!/usr/bin/env python3
"""
Quick fix for admin password hash
"""

import mysql.connector
from werkzeug.security import generate_password_hash

try:
    connection = mysql.connector.connect(
        host='localhost',
        user='root',
        password='samarth@2904',
        database='InsiderThreatDB'
    )
    
    cursor = connection.cursor()
    
    # Generate proper password hash
    password_hash = generate_password_hash('admin123')
    
    # Update admin password
    cursor.execute("UPDATE users SET password_hash = %s WHERE username = 'admin'", (password_hash,))
    connection.commit()
    
    print("[SUCCESS] Admin password fixed successfully!")
    print("[INFO] Login: admin / admin123")
    
    cursor.close()
    connection.close()
    
except Exception as e:
    print(f"[ERROR] Error: {e}")