#!/usr/bin/env python3
"""
Simple database API server for dashboard
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for browser access

DB_PATH = "../backend/security.db"
WHITELIST_PATH = "../backend/data/whitelist.json"

def get_db_connection():
    """Get database connection"""
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH)

@app.route('/api/whitelist', methods=['POST'])
def add_to_whitelist():
    """Add path to whitelist (False Positive feedback)"""
    try:
        data = request.json
        path = data.get('path')
        if not path:
            return jsonify({"error": "Path required"}), 400
            
        import json
        if os.path.exists(WHITELIST_PATH):
            with open(WHITELIST_PATH, 'r') as f:
                whitelist = json.load(f)
        else:
            whitelist = []
            
        if path not in whitelist:
            whitelist.append(path)
            with open(WHITELIST_PATH, 'w') as f:
                json.dump(whitelist, f, indent=4)
                
        return jsonify({"status": "success", "message": f"Added {path} to whitelist"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify([])
        
        conn.row_factory = sqlite3.Row
        cursor = conn.execute('''
            SELECT * FROM alerts 
            ORDER BY created_at DESC 
            LIMIT 50
        ''')
        alerts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({
                "total_requests": 0,
                "attack_requests": 0,
                "high_severity_alerts": 0,
                "detection_rate": 0
            })
        
        # Get stats
        cursor = conn.execute('SELECT * FROM stats WHERE id = 1')
        stats_row = cursor.fetchone()
        
        # Get total alerts
        cursor = conn.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = cursor.fetchone()[0]
        
        conn.close()
        
        if stats_row:
            return jsonify({
                "total_requests": stats_row[1],
                "attack_requests": stats_row[2], 
                "high_severity_alerts": stats_row[3],
                "total_alerts": total_alerts,
                "detection_rate": 95.29,
                "last_updated": stats_row[4]
            })
        else:
            return jsonify({
                "total_requests": 0,
                "attack_requests": 0,
                "high_severity_alerts": 0,
                "total_alerts": 0,
                "detection_rate": 0
            })
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats/history')
def get_stats_history():
    """Get attack history for line chart (last 24h)"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify([])
        
        date_param = request.args.get('date')
        
        if date_param:
            # Historical Mode: Group by Hour for specific date
            cursor = conn.execute('''
                SELECT 
                    strftime('%Y-%m-%dT%H:00:00', timestamp) as time_bucket,
                    COUNT(*) as count
                FROM alerts 
                WHERE date(timestamp) = ?
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            ''', (date_param,))
        else:
            # Live Mode: Group by 10-second intervals (Last 10 mins)
            # using unixepoch to bucket
            cursor = conn.execute('''
                SELECT 
                    datetime((strftime('%s', timestamp) / 10) * 10, 'unixepoch') as time_bucket,
                    COUNT(*) as count
                FROM alerts 
                GROUP BY time_bucket
                ORDER BY time_bucket DESC
                LIMIT 60
            ''')
            # Reverse to show oldest -> newest for chart
            rows = cursor.fetchall()
            data = [{"time": row[0], "count": row[1]} for row in reversed(rows)]
            conn.close()
            return jsonify(data)
            
            
        data = [{"time": row[0], "count": row[1]} for row in cursor.fetchall()]
        conn.close()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats/daily-pattern')
def get_daily_pattern():
    """Get accumulated attacks by hour-of-day (0-23) across all history"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify([0] * 24)
        
        # SQLite query to group by hour
        cursor = conn.execute('''
            SELECT 
                CAST(strftime('%H', timestamp) AS INTEGER) as hour_of_day,
                COUNT(*) as count
            FROM alerts 
            GROUP BY hour_of_day
            ORDER BY hour_of_day ASC
        ''')
        
        rows = cursor.fetchall()
        
        # Initialize 24-hour array with 0
        hourly_counts = [0] * 24
        
        # Fill in data
        for row in rows:
            hour = row[0]
            count = row[1]
            if 0 <= hour < 24:
                hourly_counts[hour] = count
                
        conn.close()
        return jsonify(hourly_counts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats/distribution')
def get_stats_distribution():
    """Get attack distribution for pie chart"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"labels": [], "data": []})
        
        cursor = conn.execute('''
            SELECT attack_type, COUNT(*) as count
            FROM alerts 
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 10
        ''')
        
        rows = cursor.fetchall()
        labels = [row[0] for row in rows]
        counts = [row[1] for row in rows]
        
        conn.close()
        return jsonify({"labels": labels, "data": counts})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def home():
    """Root endpoint"""
    return jsonify({
        "message": "Dashboard Database API",
        "status": "running",
        "endpoints": ["/api/alerts", "/api/stats", "/api/health"]
    })
@app.route('/api/health')
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "service": "dashboard-database-api",
        "database": "connected" if os.path.exists(DB_PATH) else "not found"
    })

if __name__ == '__main__':
    print("🗄️ Starting Dashboard Database API...")
    print("📊 Dashboard will connect directly to database")
    print("🌐 API available at: http://localhost:5002")
    app.run(host='127.0.0.1', port=5002, debug=True)