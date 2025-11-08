import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime, timedelta
from config import MODEL_CONFIG, MODELS_DIR
import logging

class BehavioralAI:
    def __init__(self, db_manager):
        self.db = db_manager
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = os.path.join(MODELS_DIR, 'behavioral_model.pkl')
        self.scaler_path = os.path.join(MODELS_DIR, 'behavioral_scaler.pkl')
        self.load_model()
    
    def extract_features(self, user_id, days=7):
        """Extract behavioral features for a user"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        query = """
        SELECT 
            DATE(timestamp) as date,
            COUNT(*) as total_events,
            SUM(CASE WHEN event_type = 'file_access' THEN 1 ELSE 0 END) as file_access_count,
            SUM(CASE WHEN event_type = 'network_activity' THEN 1 ELSE 0 END) as network_count,
            SUM(CASE WHEN event_type = 'failed_login' THEN 1 ELSE 0 END) as failed_logins,
            SUM(bytes_transferred) as total_bytes,
            COUNT(DISTINCT HOUR(timestamp)) as active_hours,
            SUM(CASE WHEN HOUR(timestamp) < 8 OR HOUR(timestamp) > 18 THEN 1 ELSE 0 END) as off_hours_activity
        FROM activity_logs 
        WHERE user_id = %s AND timestamp BETWEEN %s AND %s
        GROUP BY DATE(timestamp)
        ORDER BY date
        """
        
        results = self.db.execute_query(query, (user_id, start_date, end_date))
        
        if not results:
            return np.array([[0, 0, 0, 0, 0, 0, 0]])
        
        features = []
        for row in results:
            features.append([
                row['total_events'],
                row['file_access_count'],
                row['network_count'],
                row['failed_logins'],
                row['total_bytes'],
                row['active_hours'],
                row['off_hours_activity']
            ])
        
        return np.array(features)
    
    def train_model(self, user_id):
        """Train the behavioral model for a user"""
        features = self.extract_features(user_id, days=MODEL_CONFIG['learning_period_days'])
        
        if len(features) < 3:
            logging.warning(f"Insufficient data to train model for user {user_id}")
            return False
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train isolation forest
        self.model.fit(features_scaled)
        self.is_trained = True
        
        # Save model
        self.save_model()
        
        # Update user baseline
        baseline_data = {
            'avg_daily_file_access': int(np.mean(features[:, 1])),
            'avg_daily_network_activity': int(np.mean(features[:, 4])),
            'typical_work_hours_start': '09:00:00',
            'typical_work_hours_end': '17:00:00'
        }
        self.db.update_user_baseline(user_id, baseline_data)
        
        logging.info(f"Model trained successfully for user {user_id}")
        return True
    
    def detect_anomaly(self, user_id, current_features):
        """Detect if current behavior is anomalous"""
        if not self.is_trained:
            return 0.0
        
        try:
            features_scaled = self.scaler.transform([current_features])
            anomaly_score = self.model.decision_function(features_scaled)[0]
            is_anomaly = self.model.predict(features_scaled)[0] == -1
            
            # Convert to probability-like score (0-1)
            normalized_score = max(0, min(1, (0.5 - anomaly_score) * 2))
            
            return normalized_score if is_anomaly else 0.0
        except Exception as e:
            logging.error(f"Anomaly detection error: {e}")
            return 0.0
    
    def analyze_current_behavior(self, user_id):
        """Analyze current user behavior and return anomaly score"""
        # Get today's features
        today_features = self.extract_features(user_id, days=1)
        
        if len(today_features) == 0:
            return 0.0
        
        current_features = today_features[-1]  # Latest day
        anomaly_score = self.detect_anomaly(user_id, current_features)
        
        # Check specific anomaly patterns
        baseline = self.db.get_user_baseline(user_id)
        if baseline:
            # File access spike
            if current_features[1] > baseline['avg_daily_file_access'] * 3:
                anomaly_score = max(anomaly_score, 0.8)
            
            # Network activity spike
            if current_features[4] > baseline['avg_daily_network_activity'] * 5:
                anomaly_score = max(anomaly_score, 0.9)
            
            # Off-hours activity
            if current_features[6] > 10:
                anomaly_score = max(anomaly_score, 0.7)
        
        return anomaly_score
    
    def save_model(self):
        """Save trained model and scaler"""
        try:
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            logging.info("Model saved successfully")
        except Exception as e:
            logging.error(f"Error saving model: {e}")
    
    def load_model(self):
        """Load trained model and scaler"""
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                self.is_trained = True
                logging.info("Model loaded successfully")
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            self.is_trained = False