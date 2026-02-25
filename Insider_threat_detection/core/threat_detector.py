from datetime import datetime, timedelta
from core.database import DatabaseManager
from core.behavioral_ai import BehavioralAI
from config import ALERT_CONFIG, MODEL_CONFIG
from notifications import SystemNotifications
import logging

class ThreatDetector:
    def __init__(self):
        self.db = DatabaseManager()
        self.ai = BehavioralAI(self.db)
        self.failed_login_attempts = {}
        
    def handle_usb_connection(self, drive_path):
        """Handle USB device connection"""
        try:
            current_user_id = self.get_current_user_id()
            
            # Log USB connection
            self.db.log_activity(
                current_user_id, 
                'usb_connect',
                device_info=drive_path,
                outcome='success'
            )
            
            # Create alert for USB connection
            self.db.create_alert(
                current_user_id,
                'usb_connection',
                'high',
                'USB Device Connected',
                f'USB device connected at {drive_path}',
                {'drive_path': drive_path, 'timestamp': datetime.now().isoformat()}
            )
            
            # Show single popup notification
            SystemNotifications.show_usb_alert(drive_path)
            
            logging.warning(f"USB ALERT: Device connected at {drive_path}")
            
        except Exception as e:
            logging.error(f"USB connection handling error: {e}")
    
    def handle_usb_disconnection(self, drive_path):
        """Handle USB device disconnection"""
        try:
            current_user_id = self.get_current_user_id()
            
            # Log USB disconnection
            self.db.log_activity(
                current_user_id,
                'usb_disconnect',
                device_info=drive_path,
                outcome='success'
            )
            
            # Create alert for USB removal
            self.db.create_alert(
                current_user_id,
                'usb_disconnection',
                'low',
                'USB Device Removed',
                f'USB device safely removed from {drive_path}',
                {'drive_path': drive_path, 'timestamp': datetime.now().isoformat()}
            )
            
            logging.info(f"USB disconnected: {drive_path}")
            
        except Exception as e:
            logging.error(f"USB disconnection handling error: {e}")
    
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
                'critical',
                'Restricted File Access Attempt',
                f'Attempted {event_type} on restricted file: {file_path}',
                {'file_path': file_path, 'event_type': event_type}
            )
            

            
            # Show single popup notification
            SystemNotifications.show_file_restriction_alert(file_path, event_type)
            
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
            if not file_path or not isinstance(file_path, str):
                return
                
            current_user_id = self.get_current_user_id()
            
            # Get restricted paths from database
            restricted_paths = self.get_restricted_paths()
            
            # Check if file path matches any restricted path
            is_restricted = False
            for restricted_path in restricted_paths:
                if file_path.lower().startswith(restricted_path.lower()):
                    is_restricted = True
                    break
            
            if is_restricted:
                self.handle_restricted_access(current_user_id, file_path, event_type)
                logging.warning(f"RESTRICTED ACCESS DETECTED: {event_type} on {file_path}")
                
        except Exception as e:
            logging.error(f"Fast file access check error: {e}")
    
    def handle_usb_connection_fast(self, drive_path, device_info=None):
        """Fast USB connection handling"""
        try:
            if not drive_path:
                return
                
            current_user_id = self.get_current_user_id()
            
            if device_info and isinstance(device_info, dict):
                label = device_info.get('label', 'USB Device')
                device_type = device_info.get('type', 'USB Storage')
                title = f'{device_type} Connected: {label}'
                description = f'{device_type} "{label}" connected at {drive_path}'
            else:
                title = 'USB Device Connected'
                description = f'USB device connected at {drive_path}'
            
            # Create alert
            alert_id = self.db.create_alert(
                current_user_id,
                'usb_connection',
                'high',
                title,
                description,
                {'drive_path': drive_path, 'device_info': device_info, 'detection_type': 'fast'}
            )
            
            if alert_id:
                # Show single popup notification
                device_name = device_info.get('label', 'USB Device') if isinstance(device_info, dict) else 'USB Device'
                SystemNotifications.show_usb_alert(drive_path, device_name)
                logging.warning(f"USB CONNECTION ALERT: {title} at {drive_path} - Alert ID: {alert_id}")
            else:
                logging.warning(f"Failed to create USB connection alert for {drive_path}")
            
        except Exception as e:
            logging.error(f"Fast USB connection handling error: {e}")
    
    def handle_usb_disconnection_fast(self, drive_path):
        """Fast USB disconnection handling"""
        try:
            if not drive_path:
                return
                
            current_user_id = self.get_current_user_id()
            
            # Log disconnection
            self.db.log_activity(current_user_id, 'usb_disconnect', device_info=drive_path)
            
            # Create removal alert
            alert_id = self.db.create_alert(
                current_user_id,
                'usb_disconnection',
                'info',
                'USB Device Removed',
                f'USB device safely removed from {drive_path}',
                {'drive_path': drive_path, 'detection_type': 'fast'}
            )
            
            if alert_id:
                logging.info(f"USB REMOVAL ALERT: {drive_path} - Alert ID: {alert_id}")
            else:
                logging.warning(f"Failed to create USB removal alert for {drive_path}")
                
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
    
    def get_restricted_paths(self):
        """Get list of restricted paths from database"""
        try:
            if self.db:
                restricted = self.db.get_restricted_resources()
                if restricted:
                    return [r['resource_path'] for r in restricted]
            # Default restricted paths if database unavailable
            return ['C:\\confidential', 'C:\\sensitive', 'C:\\restricted']
        except Exception as e:
            logging.error(f"Error getting restricted paths: {e}")
            return ['C:\\confidential', 'C:\\sensitive', 'C:\\restricted']
    
    def close(self):
        """Close database connections"""
        self.db.close()