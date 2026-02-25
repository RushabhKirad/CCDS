import mysql.connector
from mysql.connector import Error
import json
from datetime import datetime, timedelta
from config import DB_CONFIG
import logging

class DatabaseManager:
    def __init__(self):
        self.connection = None
        self.pool = None
        self.connect()
    
    def connect(self):
        try:
            from mysql.connector import pooling
            # Create pool config without duplicate pool_size
            pool_config = DB_CONFIG.copy()
            pool_config.pop('pool_size', None)
            pool_config.pop('pool_reset_session', None)
            
            self.pool = pooling.MySQLConnectionPool(
                pool_name="insider_threat_pool",
                pool_size=5,
                **pool_config
            )
            self.connection = self.pool.get_connection()
            if self.connection.is_connected():
                logging.info("Connected to MySQL database with pooling")
        except Error as e:
            logging.error(f"Database connection error: {e}")
            # Fallback to direct connection
            try:
                direct_config = DB_CONFIG.copy()
                direct_config.pop('pool_size', None)
                direct_config.pop('pool_reset_session', None)
                self.connection = mysql.connector.connect(**direct_config)
                if self.connection.is_connected():
                    logging.info("Connected to MySQL database (direct)")
            except Error as e2:
                logging.error(f"Direct connection also failed: {e2}")
    
    def execute_query(self, query, params=None):
        cursor = None
        connection = None
        try:
            # Get fresh connection from pool
            if self.pool:
                try:
                    connection = self.pool.get_connection()
                except:
                    self.connect()
                    connection = self.pool.get_connection() if self.pool else self.connection
            else:
                connection = self.connection
                if not connection or not connection.is_connected():
                    self.connect()
                    connection = self.connection
            
            if not connection or not connection.is_connected():
                logging.error("No database connection available")
                return None
                
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, params)
            if query.strip().upper().startswith('SELECT'):
                result = cursor.fetchall()
                return result
            else:
                connection.commit()
                return cursor.lastrowid
        except Error as e:
            logging.error(f"Query execution error: {e}")
            if "Lost connection" in str(e) or "MySQL server has gone away" in str(e) or "SSL" in str(e):
                try:
                    self.connect()
                except:
                    pass
            return None
        finally:
            if cursor:
                cursor.close()
            if connection and self.pool and connection != self.connection:
                connection.close()
    
    def get_user_by_username(self, username):
        query = """
        SELECT u.*, o.org_name 
        FROM users u 
        JOIN organizations o ON u.org_id = o.id 
        WHERE u.username = %s AND u.is_active = TRUE
        """
        return self.execute_query(query, (username,))
    
    def log_activity(self, user_id, event_type, **kwargs):
        query = """
        INSERT INTO activity_logs (user_id, timestamp, event_type, file_path, 
                                 process_name, network_destination, bytes_transferred, 
                                 device_info, outcome, anomaly_score)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (
            user_id,
            datetime.now(),
            event_type,
            kwargs.get('file_path'),
            kwargs.get('process_name'),
            kwargs.get('network_destination'),
            kwargs.get('bytes_transferred', 0),
            kwargs.get('device_info'),
            kwargs.get('outcome', 'success'),
            kwargs.get('anomaly_score', 0.0)
        )
        return self.execute_query(query, params)
    
    def create_alert(self, user_id, alert_type, severity, title, description, metadata=None):
        # Check for duplicate alerts in last 30 seconds
        check_query = """
        SELECT id FROM alerts 
        WHERE user_id = %s AND alert_type = %s AND title = %s 
        AND created_at > DATE_SUB(NOW(), INTERVAL 30 SECOND)
        LIMIT 1
        """
        existing = self.execute_query(check_query, (user_id, alert_type, title))
        
        if existing:
            return existing[0]['id']  # Return existing alert ID
        
        query = """
        INSERT INTO alerts (user_id, alert_type, severity, title, description, metadata)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        params = (user_id, alert_type, severity, title, description, json.dumps(metadata) if metadata else None)
        return self.execute_query(query, params)
    
    def get_user_baseline(self, user_id):
        query = "SELECT * FROM user_baselines WHERE user_id = %s"
        result = self.execute_query(query, (user_id,))
        return result[0] if result else None
    
    def update_user_baseline(self, user_id, baseline_data):
        query = """
        INSERT INTO user_baselines (user_id, avg_daily_file_access, avg_daily_network_activity,
                                  typical_work_hours_start, typical_work_hours_end,
                                  common_file_types, common_applications)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        avg_daily_file_access = VALUES(avg_daily_file_access),
        avg_daily_network_activity = VALUES(avg_daily_network_activity),
        typical_work_hours_start = VALUES(typical_work_hours_start),
        typical_work_hours_end = VALUES(typical_work_hours_end),
        common_file_types = VALUES(common_file_types),
        common_applications = VALUES(common_applications),
        baseline_updated_at = CURRENT_TIMESTAMP
        """
        params = (
            user_id,
            baseline_data.get('avg_daily_file_access', 0),
            baseline_data.get('avg_daily_network_activity', 0),
            baseline_data.get('typical_work_hours_start', '09:00:00'),
            baseline_data.get('typical_work_hours_end', '17:00:00'),
            json.dumps(baseline_data.get('common_file_types', [])),
            json.dumps(baseline_data.get('common_applications', []))
        )
        return self.execute_query(query, params)
    
    def get_recent_alerts(self, limit=50):
        query = """
        SELECT a.*, u.username, u.full_name, o.org_name
        FROM alerts a
        JOIN users u ON a.user_id = u.id
        JOIN organizations o ON u.org_id = o.id
        ORDER BY a.created_at DESC
        LIMIT %s
        """
        return self.execute_query(query, (limit,))
    
    def get_restricted_resources(self):
        query = "SELECT * FROM restricted_resources"
        return self.execute_query(query)
    
    def close(self):
        if self.connection and self.connection.is_connected():
            self.connection.close()
            logging.info("Database connection closed")