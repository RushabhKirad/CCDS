from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash
from core.database import DatabaseManager
from core.threat_detector import ThreatDetector
from core.elite_monitor import EliteMonitoringSystem
import json
import os
from datetime import datetime, timedelta
import threading
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# Initialize core components
db = DatabaseManager()
threat_detector = ThreatDetector()
elite_monitor = EliteMonitoringSystem(threat_detector)

# Start monitoring in background
monitoring_thread = None

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    # Get recent alerts with error handling
    alerts = []
    alert_stats = {'today_total': 0, 'unacknowledged': 0, 'severity_breakdown': {}}
    activity_summary = []
    
    try:
        if db and db.connection and db.connection.is_connected():
            alerts = db.get_recent_alerts(20) or []
            alert_stats = get_alert_statistics()
            user_id = session.get('user_id', 1)
            activity_summary = get_activity_summary(user_id)
    except Exception as e:
        logging.error(f"Dashboard data error: {e}")
    
    # Create default user context for template
    user_context = session if 'user_id' in session else {'role': 'viewer', 'full_name': 'Security Monitor'}
    
    return render_template('dashboard.html', 
                         alerts=alerts, 
                         alert_stats=alert_stats,
                         activity_summary=activity_summary,
                         user=user_context)

@app.route('/api/alerts')
def api_alerts():
    try:
        alerts = []
        if db:
            alerts = db.get_recent_alerts(50) or []
        return jsonify(alerts)
    except Exception as e:
        logging.error(f"API alerts error: {e}")
        return jsonify([])

@app.route('/admin_panel')
def admin_panel():
    user_context = session if 'user_id' in session else {'role': 'admin', 'full_name': 'Admin'}
    return render_template('admin_panel.html', user=user_context)

@app.route('/api/browse_files', methods=['POST'])
def browse_files():
    path = request.json.get('path', 'C:\\') if request.json else 'C:\\'
    files = []
    
    try:
        restricted_paths = set()
        try:
            if db and db.connection and db.connection.is_connected():
                restricted = db.get_restricted_resources()
                if restricted:
                    restricted_paths = {r['resource_path'] for r in restricted}
        except Exception:
            pass
        
        for item in os.listdir(path):
            try:
                item_path = os.path.join(path, item)
                is_dir = os.path.isdir(item_path)
                is_restricted = any(item_path.startswith(rp) for rp in restricted_paths)
                
                files.append({
                    'name': item,
                    'path': item_path,
                    'type': 'folder' if is_dir else 'file',
                    'restricted': is_restricted
                })
            except Exception:
                continue
        
        files.sort(key=lambda x: (x['type'] != 'folder', x['name'].lower()))
        return jsonify({'files': files})
        
    except Exception as e:
        return jsonify({'error': f'Cannot access path: {str(e)}'}), 500

@app.route('/api/add_restriction', methods=['POST'])
def add_restriction():
    data = request.json if request.json else {}
    path = data.get('path')
    level = data.get('level', 'no_access')
    description = data.get('description', 'Restricted by admin')
    
    if not path:
        return jsonify({'error': 'Path is required'}), 400
    
    try:
        resource_type = 'folder' if os.path.isdir(path) else 'file'
        
        query = """
        INSERT INTO restricted_resources (resource_path, resource_type, restriction_level, description)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE 
        restriction_level = VALUES(restriction_level),
        description = VALUES(description)
        """
        
        if db and db.connection and db.connection.is_connected():
            result = db.execute_query(query, (path, resource_type, level, description))
            
            if result is not None:
                logging.info(f"RESTRICTION ADDED: {path}")
                return jsonify({'success': True, 'message': f'Restriction added to {path}'})
            else:
                return jsonify({'error': 'Failed to add restriction'}), 500
        else:
            return jsonify({'error': 'Database not available'}), 500
            
    except Exception as e:
        logging.error(f"Add restriction error: {e}")
        return jsonify({'error': str(e)}), 500

def get_alert_statistics():
    try:
        today = datetime.now().date()
        query = "SELECT COUNT(*) as count FROM alerts WHERE DATE(created_at) = %s"
        today_alerts = db.execute_query(query, (today,))
        
        query = "SELECT COUNT(*) as count FROM alerts WHERE is_acknowledged = FALSE"
        unack_alerts = db.execute_query(query)
        
        return {
            'today_total': today_alerts[0]['count'] if today_alerts else 0,
            'unacknowledged': unack_alerts[0]['count'] if unack_alerts else 0,
            'severity_breakdown': {}
        }
    except Exception as e:
        logging.error(f"Error getting alert statistics: {e}")
        return {'today_total': 0, 'unacknowledged': 0, 'severity_breakdown': {}}

def get_activity_summary(user_id):
    try:
        today = datetime.now().date()
        query = """
        SELECT event_type, COUNT(*) as count
        FROM activity_logs 
        WHERE user_id = %s AND DATE(timestamp) = %s
        GROUP BY event_type
        """
        
        activity = db.execute_query(query, (user_id, today))
        return activity if activity else []
    except Exception as e:
        logging.error(f"Error getting activity summary: {e}")
        return []

def clean_startup():
    try:
        print("[CLEANUP] Fixing database and clearing old alerts...")
        
        # Fix database column sizes
        db.execute_query("ALTER TABLE activity_logs MODIFY COLUMN event_type VARCHAR(50)")
        db.execute_query("ALTER TABLE alerts MODIFY COLUMN alert_type VARCHAR(50)")
        db.execute_query("ALTER TABLE alerts MODIFY COLUMN severity VARCHAR(20)")
        
        # Clear old alerts and logs
        db.execute_query("DELETE FROM alerts")
        db.execute_query("DELETE FROM activity_logs")
        db.execute_query("ALTER TABLE alerts AUTO_INCREMENT = 1")
        db.execute_query("ALTER TABLE activity_logs AUTO_INCREMENT = 1")
        
        # Add system startup marker
        db.create_alert(
            1, 'system_startup', 'info', 
            'Elite System Started', 
            'Elite Monitoring System - Only REAL user actions trigger alerts',
            {'startup_time': datetime.now().isoformat(), 'version': 'ELITE'}
        )
        
        print("[OK] System cleaned - Only REAL user actions will trigger alerts")
        
    except Exception as e:
        print(f"[ERROR] Cleanup failed: {e}")

if __name__ == '__main__':
    print("ELITE INSIDER THREAT DETECTION SYSTEM")
    print("=====================================")
    print("Dashboard: http://localhost:5000")
    
    # Clean startup
    clean_startup()
    
    # Start elite monitoring
    try:
        monitoring_thread = threading.Thread(target=elite_monitor.start_all_monitoring)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        print("[OK] ELITE MONITORING ACTIVE")
        print("[OK] Only REAL user actions trigger alerts")
        print("[OK] 30-second alert cooldown")
        print("[OK] Smart USB detection")
        time.sleep(2)
    except Exception as e:
        print(f"[ERROR] Monitoring start error: {e}")
    
    print("\nREADY: Only real user file access will create alerts!")
    print("TEST: Add C:\\$Recycle.Bin as restricted, then open it")
    
    try:
        app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
    except KeyboardInterrupt:
        print("\nSystem shutdown...")
        if elite_monitor:
            elite_monitor.stop_all_monitoring()
        print("[OK] Stopped safely")
    except Exception as e:
        print(f"[ERROR] System error: {e}")
        if elite_monitor:
            elite_monitor.stop_all_monitoring()