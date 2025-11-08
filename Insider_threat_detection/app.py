from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash
from core.database import DatabaseManager
from core.threat_detector import ThreatDetector
from core.file_monitor import FileMonitor
from core.fast_monitor import FastMonitoringSystem
from core.device_monitor import DeviceMonitor
import json
import os
from datetime import datetime, timedelta
import threading
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# Initialize core components
db = DatabaseManager()
threat_detector = ThreatDetector()
file_monitor = FileMonitor(threat_detector)
fast_monitor = FastMonitoringSystem(threat_detector)
device_monitor = DeviceMonitor(threat_detector)

# Start monitoring in background
monitoring_thread = None

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Handle login attempt through threat detector
        success = threat_detector.handle_login_attempt(username, success=False)  # First assume failed
        
        user_data = db.get_user_by_username(username)
        if user_data and check_password_hash(user_data[0]['password_hash'], password):
            # Successful login
            threat_detector.handle_login_attempt(username, success=True)
            
            session['user_id'] = user_data[0]['id']
            session['username'] = user_data[0]['username']
            session['full_name'] = user_data[0]['full_name']
            session['role'] = user_data[0]['role']
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Log logout activity
        db.log_activity(session['user_id'], 'logout', outcome='success')
    
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    # Get recent alerts
    alerts = db.get_recent_alerts(20)
    
    # Get alert statistics
    alert_stats = get_alert_statistics()
    
    # Get user activity summary (use default user if no session)
    user_id = session.get('user_id', 1)
    activity_summary = get_activity_summary(user_id)
    
    # Create default user context for template
    user_context = session if 'user_id' in session else {'role': 'viewer', 'full_name': 'Security Monitor'}
    
    return render_template('dashboard.html', 
                         alerts=alerts, 
                         alert_stats=alert_stats,
                         activity_summary=activity_summary,
                         user=user_context)

@app.route('/api/alerts')
def api_alerts():
    alerts = db.get_recent_alerts(50)
    return jsonify(alerts)

@app.route('/api/alert_stats')
def api_alert_stats():
    stats = get_alert_statistics()
    return jsonify(stats)

@app.route('/api/acknowledge_alert', methods=['POST'])
def acknowledge_alert():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    alert_id = request.json.get('alert_id')
    
    query = """
    UPDATE alerts 
    SET is_acknowledged = TRUE, acknowledged_by = %s, acknowledged_at = %s
    WHERE id = %s
    """
    
    db.execute_query(query, (session['user_id'], datetime.now(), alert_id))
    
    return jsonify({'success': True})

@app.route('/api/test_usb')
def test_usb():
    """Test endpoint to simulate USB connection"""
    threat_detector.handle_usb_connection('E:\\')
    return jsonify({'message': 'USB test alert created'})

@app.route('/api/test_restricted_access')
def test_restricted_access():
    """Test endpoint to simulate restricted file access"""
    user_id = session.get('user_id', 1)
    threat_detector.handle_restricted_access(
        user_id, 
        'C:\\confidential\\secret.txt', 
        'file_access'
    )
    return jsonify({'message': 'Restricted access test alert created'})

@app.route('/admin_panel')
def admin_panel():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    return render_template('admin_panel.html', user=session)

@app.route('/api/browse_files', methods=['POST'])
def browse_files():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    path = request.json.get('path', 'C:\\')
    files = []
    
    try:
        # Get restricted paths from database
        restricted = db.get_restricted_resources()
        restricted_paths = {r['resource_path'] for r in restricted}
        
        for item in os.listdir(path):
            item_path = os.path.join(path, item)
            is_dir = os.path.isdir(item_path)
            is_restricted = any(item_path.startswith(rp) for rp in restricted_paths)
            
            files.append({
                'name': item,
                'path': item_path,
                'type': 'folder' if is_dir else 'file',
                'restricted': is_restricted
            })
        
        files.sort(key=lambda x: (x['type'] != 'folder', x['name'].lower()))
        return jsonify({'files': files})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/add_restriction', methods=['POST'])
def add_restriction():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    path = data.get('path')
    level = data.get('level', 'no_access')
    description = data.get('description', '')
    
    resource_type = 'folder' if os.path.isdir(path) else 'file'
    
    query = """
    INSERT INTO restricted_resources (resource_path, resource_type, restriction_level, description)
    VALUES (%s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE 
    restriction_level = VALUES(restriction_level),
    description = VALUES(description)
    """
    
    result = db.execute_query(query, (path, resource_type, level, description))
    
    if result is not None:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Failed to add restriction'}), 500

@app.route('/api/remove_restriction', methods=['POST'])
def remove_restriction():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    path = request.json.get('path')
    
    query = "DELETE FROM restricted_resources WHERE resource_path = %s"
    result = db.execute_query(query, (path,))
    
    return jsonify({'success': True})

@app.route('/api/get_restrictions')
def get_restrictions():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    restrictions = db.get_restricted_resources()
    return jsonify({'restrictions': restrictions})

@app.route('/api/delete_restriction', methods=['POST'])
def delete_restriction():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    restriction_id = request.json.get('id')
    
    query = "DELETE FROM restricted_resources WHERE id = %s"
    result = db.execute_query(query, (restriction_id,))
    
    return jsonify({'success': True})

@app.route('/start_monitoring')
def start_monitoring():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    global monitoring_thread
    if monitoring_thread is None or not monitoring_thread.is_alive():
        # Start all monitoring systems
        monitoring_thread = threading.Thread(target=lambda: [
            fast_monitor.start_all_monitoring(),
            device_monitor.start_monitoring()
        ])
        monitoring_thread.daemon = True
        monitoring_thread.start()
        return jsonify({'message': 'All monitoring systems started'})
    else:
        return jsonify({'message': 'Monitoring already running'})

@app.route('/stop_monitoring')
def stop_monitoring():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
    
    file_monitor.stop_monitoring()
    fast_monitor.stop_all_monitoring()
    device_monitor.stop_monitoring()
    return jsonify({'message': 'All monitoring systems stopped'})

def get_alert_statistics():
    """Get alert statistics for dashboard"""
    try:
        # Total alerts today
        today = datetime.now().date()
        query = "SELECT COUNT(*) as count FROM alerts WHERE DATE(created_at) = %s"
        today_alerts = db.execute_query(query, (today,))
        
        # Alerts by severity
        query = """
        SELECT severity, COUNT(*) as count 
        FROM alerts 
        WHERE created_at >= %s 
        GROUP BY severity
        """
        week_ago = datetime.now() - timedelta(days=7)
        severity_stats = db.execute_query(query, (week_ago,))
        
        # Unacknowledged alerts
        query = "SELECT COUNT(*) as count FROM alerts WHERE is_acknowledged = FALSE"
        unack_alerts = db.execute_query(query)
        
        return {
            'today_total': today_alerts[0]['count'] if today_alerts else 0,
            'unacknowledged': unack_alerts[0]['count'] if unack_alerts else 0,
            'severity_breakdown': {row['severity']: row['count'] for row in severity_stats} if severity_stats else {}
        }
    except Exception as e:
        logging.error(f"Error getting alert statistics: {e}")
        return {'today_total': 0, 'unacknowledged': 0, 'severity_breakdown': {}}

def get_activity_summary(user_id):
    """Get user activity summary"""
    try:
        today = datetime.now().date()
        query = """
        SELECT 
            event_type,
            COUNT(*) as count,
            AVG(anomaly_score) as avg_anomaly_score
        FROM activity_logs 
        WHERE user_id = %s AND DATE(timestamp) = %s
        GROUP BY event_type
        """
        
        activity = db.execute_query(query, (user_id, today))
        return activity if activity else []
    except Exception as e:
        logging.error(f"Error getting activity summary: {e}")
        return []

@app.route('/health')
def health_check():
    """Health check endpoint for module integration"""
    return jsonify({
        'status': 'healthy',
        'service': 'insider-threat-detection',
        'version': '1.0.0',
        'port': 5002
    })

@app.route('/api/performance_metrics')
def performance_metrics():
    
    # Detection accuracy
    query = """
    SELECT 
        alert_type,
        COUNT(*) as total_alerts,
        COUNT(CASE WHEN is_acknowledged = TRUE THEN 1 END) as confirmed_alerts,
        ROUND(COUNT(CASE WHEN is_acknowledged = TRUE THEN 1 END) * 100.0 / COUNT(*), 2) as accuracy_rate
    FROM alerts 
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    GROUP BY alert_type
    """
    accuracy_data = db.execute_query(query)
    
    # Response times
    query = """
    SELECT 
        AVG(TIMESTAMPDIFF(SECOND, created_at, acknowledged_at)) as avg_response_time,
        MIN(TIMESTAMPDIFF(SECOND, created_at, acknowledged_at)) as min_response_time,
        MAX(TIMESTAMPDIFF(SECOND, created_at, acknowledged_at)) as max_response_time
    FROM alerts 
    WHERE acknowledged_at IS NOT NULL AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    """
    response_times = db.execute_query(query)
    
    # Alert trends (last 7 days)
    query = """
    SELECT 
        DATE(created_at) as date,
        COUNT(*) as alert_count,
        COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count
    FROM alerts 
    WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    GROUP BY DATE(created_at)
    ORDER BY date
    """
    alert_trends = db.execute_query(query)
    
    # System performance
    import psutil
    system_performance = {
        'cpu_usage': psutil.cpu_percent(),
        'memory_usage': psutil.virtual_memory().percent,
        'disk_usage': 45  # Simplified for demo
    }
    
    return jsonify({
        'detection_accuracy': accuracy_data or [],
        'response_times': response_times[0] if response_times else {'avg_response_time': 0, 'min_response_time': 0, 'max_response_time': 0},
        'alert_trends': alert_trends or [],
        'system_performance': system_performance
    })

@app.route('/metrics')
def metrics_dashboard():
    user_context = session if 'user_id' in session else {'role': 'viewer', 'full_name': 'Security Monitor'}
    return render_template('metrics.html', user=user_context)

if __name__ == '__main__':
    import sys
    port = 5002
    if '--port=5002' in sys.argv:
        port = 5002
    
    print("Starting Insider Threat Detection System...")
    print(f"Dashboard will be available at: http://localhost:{port}")
    print("Default login: admin / admin123")
    print("System is ready for monitoring!")
    print("Features: USB Detection, File Control, AI Learning, Metrics Dashboard")
    
    app.run(debug=True, host='0.0.0.0', port=port)