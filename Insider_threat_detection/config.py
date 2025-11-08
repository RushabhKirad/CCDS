# System Configuration
import os

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'samarth@2904',  # MySQL password
    'database': 'InsiderThreatDB',
    'charset': 'utf8mb4'
}

# Security Configuration
SECRET_KEY = 'cybersec-insider-threat-detection-2024-secure-key-samarth'
BCRYPT_ROUNDS = 12

# AI Model Configuration
MODEL_CONFIG = {
    'anomaly_threshold': 0.7,
    'learning_period_days': 7,
    'retrain_interval_hours': 24,
    'feature_window_size': 10
}

# Alert Configuration
ALERT_CONFIG = {
    'max_failed_logins': 5,
    'network_spike_threshold': 1000000,  # bytes
    'file_access_spike_threshold': 50,
    'retention_days': 90
}

# File Monitoring
MONITORED_EXTENSIONS = ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.txt', '.key', '.pem', '.p12']
RESTRICTED_PATHS = [
    'C:\\Windows\\System32\\config',
    'C:\\confidential',
    'C:\\sensitive'
]

# System Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

# Create directories if they don't exist
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)