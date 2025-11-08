import sqlite3
import json
from datetime import datetime
import threading
import os

class SecurityDatabase:
    def __init__(self, db_path="security.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            # Alerts table for ML detection results
            conn.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    source_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT,
                    user_agent TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Requests table for Cloudflare traffic
            conn.execute('''
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    user_agent TEXT,
                    is_attack BOOLEAN DEFAULT FALSE,
                    attack_type TEXT DEFAULT 'Normal',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Stats table for real-time counters
            conn.execute('''
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    total_requests INTEGER DEFAULT 0,
                    attack_requests INTEGER DEFAULT 0,
                    high_severity_attacks INTEGER DEFAULT 0,
                    last_updated TEXT
                )
            ''')
            
            # Initialize stats if empty
            conn.execute('''
                INSERT OR IGNORE INTO stats 
                (id, total_requests, attack_requests, high_severity_attacks, last_updated) 
                VALUES (1, 0, 0, 0, ?)
            ''', (datetime.now().isoformat(),))
            conn.commit()
    
    def add_alert(self, alert_data):
        """Add new security alert"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO alerts 
                    (id, timestamp, attack_type, confidence, source_ip, method, path, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    alert_data['id'],
                    alert_data['timestamp'],
                    alert_data['attack_type'],
                    alert_data['confidence'],
                    alert_data['source_ip'],
                    alert_data['method'],
                    alert_data.get('path', '/'),
                    alert_data.get('user_agent', '')
                ))
                conn.commit()
    
    def add_request(self, request_data):
        """Log request to database"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO requests 
                    (timestamp, method, path, ip, user_agent, is_attack, attack_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    request_data.get('timestamp', datetime.now().isoformat()),
                    request_data.get('method', 'GET'),
                    request_data.get('path', '/'),
                    request_data.get('ip', 'unknown'),
                    request_data.get('user_agent', ''),
                    request_data.get('is_attack', False),
                    request_data.get('attack_type', 'Normal')
                ))
                conn.commit()
    
    def increment_stats(self, requests=0, attacks=0, high_severity=0):
        """Increment statistics atomically"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    UPDATE stats SET 
                    total_requests = total_requests + ?,
                    attack_requests = attack_requests + ?,
                    high_severity_attacks = high_severity_attacks + ?,
                    last_updated = ?
                    WHERE id = 1
                ''', (requests, attacks, high_severity, datetime.now().isoformat()))
                conn.commit()
    
    def get_alerts(self, limit=50):
        """Get recent alerts"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM alerts 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_stats(self):
        """Get current statistics"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM stats WHERE id = 1')
            row = cursor.fetchone()
            if row:
                stats = dict(row)
                stats['normal_requests'] = stats['total_requests'] - stats['attack_requests']
                return stats
            return {
                'total_requests': 0,
                'attack_requests': 0,
                'normal_requests': 0,
                'high_severity_attacks': 0,
                'last_updated': datetime.now().isoformat()
            }
    
    def get_recent_requests(self, limit=100):
        """Get recent requests for analysis"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM requests 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]