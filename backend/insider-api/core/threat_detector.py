from datetime import datetime, timedelta
from core.database import DatabaseManager
from core.behavioral_ai import BehavioralAI
from config import ALERT_CONFIG, MODEL_CONFIG
import logging

class ThreatDetector:
    def __init__(self):
        self.db = DatabaseManager()
        self.ai = BehavioralAI(self.db)
        self.failed_login_attempts = {}
        
    def handle_usb_connection(self, drive_path, device_info=None):
        """Handle USB/mobile device connection"""
        try:
            current_user_id = self.get_current_user_id()
            
            if device_info is None:
                device_info = {'type': 'Unknown Device', 'name': 'Unknown'}
                
            # Determine severity based on device type
            severity = 'high' if device_info.get('type') == 'Mobile Device' else 'medium'
            
            # Log device connection with detailed info
            self.db.log_activity(
                current_user_id, 
                'device_connect',
                device_info=device_info,
                outcome='success'
            )
            
            # Create detailed alert
            device_name = device_info.get('name', 'Unknown Device')
            device_type = device_info.get('type', 'Unknown Type')
            manufacturer = device_info.get('manufacturer', 'Unknown Manufacturer')
            
            alert_title = f'{device_type} Connected'
            alert_description = (
                f"{device_type} detected:\n"
                f"Name: {device_name}\n"
                f"Manufacturer: {manufacturer}\n"
                f"Location: {drive_path}"
            )
            
            self.db.create_alert(
                current_user_id,
                'device_connection',
                severity,
                alert_title,
                alert_description,
                {
                    'drive_path': drive_path,
                    'device_info': device_info,
                    'timestamp': datetime.now().isoformat()
                }
            )
            
            logging.warning(
                f"DEVICE ALERT: {device_type} connected\n"
                f"Details: {json.dumps(device_info, indent=2)}"
            )
            
        except Exception as e:
            logging.error(f"Device connection handling error: {e}")
    
    def handle_usb_disconnection(self, drive_path, device_info=None):
        """Handle USB/mobile device disconnection"""
        try:
            current_user_id = self.get_current_user_id()
            
            if device_info is None:
                device_info = {'type': 'Unknown Device', 'name': 'Unknown'}
            
            # Log device disconnection with details
            self.db.log_activity(
                current_user_id,
                'device_disconnect',
                device_info=device_info,
                outcome='success'
            )
            
            device_type = device_info.get('type', 'Unknown Type')
            device_name = device_info.get('name', 'Unknown Device')
            
            logging.info(
                f"Device disconnected: {device_type}\n"
                f"Name: {device_name}\n"
                f"Location: {drive_path}"
            )
            
        except Exception as e:
            logging.error(f"Device disconnection handling error: {e}")
    
    def handle_usb_disconnection(self, drive_path):
        """Handle USB/Mobile device disconnection"""
        try:
            current_user_id = self.get_current_user_id()
            
            # Log device disconnection
            self.db.log_activity(
                current_user_id,
                'device_disconnect',
                device_info={'path': drive_path},
                outcome='success'
            )
            
            logging.info(f"Device disconnected: {drive_path}")
            
        except Exception as e:
            logging.error(f"Device disconnection handling error: {e}")
    
    def handle_restricted_access(self, user_id, file_path, event_type):
        """Handle access to restricted files"""
        try:
            # Log blocked access
            self.db.log_activity(
                user_id,
                event_type,
                file_path=file_path,
                outcome='blocked',
                anomaly_score=1.0
            )
            
            # Create high severity alert
            self.db.create_alert(
                user_id,
                'restricted_access',
                'high',
                'Restricted File Access Attempt',
                f'Attempted {event_type} on restricted file: {file_path}',
                {'file_path': file_path, 'event_type': event_type}
            )
            
            logging.critical(f"RESTRICTED ACCESS BLOCKED: {file_path} by user {user_id}")
            
        except Exception as e:
            logging.error(f"Restricted access handling error: {e}")
    
    def log_file_activity(self, user_id, file_path, event_type):
        """Log normal file activity and check for anomalies"""
        try:
            # Analyze behavioral anomaly
            anomaly_score = self.ai.analyze_current_behavior(user_id)
            
            # Log activity
            self.db.log_activity(
                user_id,
                event_type,
                file_path=file_path,
                outcome='success',
                anomaly_score=anomaly_score
            )
            
            # Create alert if anomaly detected
            if anomaly_score > MODEL_CONFIG['anomaly_threshold']:
                self.db.create_alert(
                    user_id,
                    'behavioral_anomaly',
                    self.get_severity_from_score(anomaly_score),
                    'Behavioral Anomaly Detected',
                    f'Unusual {event_type} pattern detected (Score: {anomaly_score:.2f})',
                    {'file_path': file_path, 'anomaly_score': anomaly_score}
                )
                
                logging.warning(f"BEHAVIORAL ANOMALY: Score {anomaly_score:.2f} for user {user_id}")
            
        except Exception as e:
            logging.error(f"File activity logging error: {e}")
    
    def handle_login_attempt(self, username, success=True):
        """Handle login attempts and detect brute force"""
        try:
            user_data = self.db.get_user_by_username(username)
            if not user_data:
                return False
            
            user_id = user_data[0]['id']
            
            if success:
                # Reset failed attempts on successful login
                if username in self.failed_login_attempts:
                    del self.failed_login_attempts[username]
                
                # Log successful login
                self.db.log_activity(user_id, 'login', outcome='success')
                
                # Train AI model if needed
                if not self.ai.is_trained:
                    self.ai.train_model(user_id)
                
                return True
            else:
                # Track failed attempts
                if username not in self.failed_login_attempts:
                    self.failed_login_attempts[username] = []
                
                self.failed_login_attempts[username].append(datetime.now())
                
                # Clean old attempts (last hour)
                cutoff = datetime.now() - timedelta(hours=1)
                self.failed_login_attempts[username] = [
                    attempt for attempt in self.failed_login_attempts[username]
                    if attempt > cutoff
                ]
                
                # Log failed login
                self.db.log_activity(user_id, 'failed_login', outcome='failed')
                
                # Check for brute force
                if len(self.failed_login_attempts[username]) >= ALERT_CONFIG['max_failed_logins']:
                    self.db.create_alert(
                        user_id,
                        'failed_login_spike',
                        'critical',
                        'Multiple Failed Login Attempts',
                        f'{len(self.failed_login_attempts[username])} failed login attempts detected',
                        {'failed_attempts': len(self.failed_login_attempts[username])}
                    )
                    
                    logging.critical(f"BRUTE FORCE DETECTED: {len(self.failed_login_attempts[username])} attempts for {username}")
                
                return False
                
        except Exception as e:
            logging.error(f"Login attempt handling error: {e}")
            return False
    
    def detect_network_anomaly(self, user_id, bytes_transferred, destination):
        """Detect network activity anomalies"""
        try:
            # Log network activity
            anomaly_score = 0.0
            
            # Check for large data transfers
            if bytes_transferred > ALERT_CONFIG['network_spike_threshold']:
                anomaly_score = 0.9
            
            # Check for suspicious destinations (simplified)
            suspicious_ips = ['192.168.', '10.', '172.']
            if not any(destination.startswith(ip) for ip in suspicious_ips):
                anomaly_score = max(anomaly_score, 0.7)
            
            self.db.log_activity(
                user_id,
                'network_activity',
                network_destination=destination,
                bytes_transferred=bytes_transferred,
                anomaly_score=anomaly_score
            )
            
            if anomaly_score > MODEL_CONFIG['anomaly_threshold']:
                self.db.create_alert(
                    user_id,
                    'network_spike',
                    self.get_severity_from_score(anomaly_score),
                    'Suspicious Network Activity',
                    f'Large data transfer detected: {bytes_transferred} bytes to {destination}',
                    {'bytes_transferred': bytes_transferred, 'destination': destination}
                )
                
                logging.warning(f"NETWORK ANOMALY: {bytes_transferred} bytes to {destination}")
            
        except Exception as e:
            logging.error(f"Network anomaly detection error: {e}")
    
    def get_current_user_id(self):
        """Get current user ID (simplified for demo)"""
        # In real implementation, this would get the actual logged-in user
        return 1  # Default admin user
    
    def get_severity_from_score(self, score):
        """Convert anomaly score to severity level"""
        if score >= 0.9:
            return 'critical'
        elif score >= 0.7:
            return 'high'
        elif score >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def cleanup_old_data(self):
        """Clean up old alerts and logs"""
        try:
            cutoff_date = datetime.now() - timedelta(days=ALERT_CONFIG['retention_days'])
            
            # Clean old alerts
            query = "DELETE FROM alerts WHERE created_at < %s"
            self.db.execute_query(query, (cutoff_date,))
            
            # Clean old activity logs (keep more for behavioral learning)
            log_cutoff = datetime.now() - timedelta(days=180)
            query = "DELETE FROM activity_logs WHERE created_at < %s"
            self.db.execute_query(query, (log_cutoff,))
            
            logging.info("Old data cleanup completed")
            
        except Exception as e:
            logging.error(f"Data cleanup error: {e}")
    
    def check_file_access_fast(self, file_path, event_type, timestamp):
        """Fast file access checking with minimal overhead"""
        try:
            current_user_id = self.get_current_user_id()
            
            # Quick restriction check
            restricted_paths = ['C:\\Windows\\System32\\config', 'C:\\confidential', 'C:\\sensitive']
            is_restricted = any(file_path.startswith(path) for path in restricted_paths)
            
            if is_restricted:
                self.handle_restricted_access(current_user_id, file_path, event_type)
            else:
                # Log with minimal processing
                self.db.log_activity(current_user_id, event_type, file_path=file_path, outcome='success')
                
        except Exception as e:
            logging.error(f"Fast file access check error: {e}")
    
    def handle_usb_connection_fast(self, drive_path):
        """Fast USB connection handling"""
        try:
            current_user_id = self.get_current_user_id()
            
            # Immediate alert creation
            self.db.create_alert(
                current_user_id,
                'usb_connection',
                'high',  # Elevated severity for fast detection
                'USB Device Connected (Fast Detection)',
                f'USB device connected at {drive_path} - Immediate detection',
                {'drive_path': drive_path, 'detection_type': 'fast'}
            )
            
            logging.warning(f"FAST USB ALERT: Device connected at {drive_path}")
            
        except Exception as e:
            logging.error(f"Fast USB connection handling error: {e}")
    
    def handle_usb_disconnection_fast(self, drive_path):
        """Fast USB disconnection handling"""
        try:
            current_user_id = self.get_current_user_id()
            self.db.log_activity(current_user_id, 'usb_disconnect', device_info=drive_path)
            logging.info(f"FAST USB: Disconnected {drive_path}")
        except Exception as e:
            logging.error(f"Fast USB disconnection error: {e}")
    
    def handle_network_spike_fast(self, interface, bytes_sent, bytes_recv):
        """Fast network spike detection"""
        try:
            current_user_id = self.get_current_user_id()
            total_bytes = bytes_sent + bytes_recv
            
            if total_bytes > 50 * 1024 * 1024:  # >50MB transfer
                self.db.create_alert(
                    current_user_id,
                    'network_spike',
                    'critical',
                    'Large Data Transfer Detected',
                    f'Massive data transfer: {total_bytes/1024/1024:.1f}MB on {interface}',
                    {'bytes_transferred': total_bytes, 'interface': interface}
                )
                
                logging.critical(f"FAST NETWORK ALERT: {total_bytes/1024/1024:.1f}MB transfer")
                
        except Exception as e:
            logging.error(f"Fast network spike handling error: {e}")
    
    def handle_suspicious_process_fast(self, process_name, process_path):
        """Fast suspicious process detection"""
        try:
            current_user_id = self.get_current_user_id()
            
            self.db.create_alert(
                current_user_id,
                'behavioral_anomaly',
                'high',
                'Suspicious Process Detected',
                f'Potentially dangerous process started: {process_name}',
                {'process_name': process_name, 'process_path': process_path}
            )
            
            logging.warning(f"FAST PROCESS ALERT: {process_name} started")
            
        except Exception as e:
            logging.error(f"Fast process detection error: {e}")
    
    def close(self):
        """Close database connections"""
        self.db.close()