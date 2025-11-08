# 🛡️ Advanced Insider Threat Detection System

## 🚀 Overview
A comprehensive AI-powered insider threat detection system that monitors user behavior, file access, USB connections, and network activity in real-time. The system uses machine learning to establish behavioral baselines and detect anomalous activities that may indicate insider threats.

## ✨ Key Features

### 🔍 Core Detection Capabilities
- **USB Device Monitoring**: Real-time detection of USB connections/disconnections
- **Restricted File Access Control**: Prevents and alerts on unauthorized file access
- **Behavioral Pattern Learning**: AI learns normal user patterns and detects anomalies
- **Network Activity Monitoring**: Detects suspicious data transfers and connections
- **Failed Login Detection**: Identifies brute force and suspicious login attempts

### 🧠 AI-Powered Analysis
- **Self-Training Models**: Isolation Forest algorithm learns user behavior automatically
- **Anomaly Scoring**: Real-time scoring of user activities (0-1 scale)
- **Behavioral Baselines**: Establishes normal patterns for each user
- **Adaptive Learning**: Continuously updates models with new data

### 📊 Professional Dashboard
- **Real-time Monitoring**: Live security alerts and system status
- **Interactive Charts**: Severity distribution and activity timelines
- **Alert Management**: Acknowledge and track security incidents
- **System Controls**: Start/stop monitoring, test alerts, refresh data

## 🏗️ System Architecture

```
├── core/
│   ├── database.py          # Database operations and queries
│   ├── behavioral_ai.py     # AI behavioral analysis engine
│   ├── file_monitor.py      # File system and USB monitoring
│   └── threat_detector.py   # Main threat detection coordinator
├── templates/
│   ├── login.html          # Secure login interface
│   └── dashboard.html      # Cybersecurity dashboard
├── models/                 # AI model storage
├── logs/                   # System logs
├── app.py                  # Main Flask application
├── config.py              # System configuration
└── CLEAN_DATABASE.sql     # Database setup script
```

## 🛠️ Installation & Setup

### 1. Database Setup
```sql
-- Run this in MySQL Workbench
mysql -u root -p < CLEAN_DATABASE.sql
```

### 2. Install Dependencies
```bash
pip install -r requirements_new.txt
```

### 3. Configure Database
Edit `config.py`:
```python
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'your_mysql_password',  # Change this
    'database': 'InsiderThreatDB',
    'charset': 'utf8mb4'
}
```

### 4. Run the System
```bash
python app.py
```

## 🔐 Access Information
- **URL**: http://localhost:5000
- **Default Login**: admin / admin123
- **Role**: Administrator

## 📋 Database Schema

### Core Tables
- **organizations**: Company/department information
- **users**: Employee accounts and profiles
- **user_baselines**: AI-learned behavioral patterns
- **activity_logs**: All user activities and events
- **alerts**: Security alerts and incidents
- **restricted_resources**: Protected files and folders

### Key Features
- **Foreign Key Constraints**: Ensures data integrity
- **Indexing**: Optimized for fast queries
- **JSON Fields**: Flexible metadata storage
- **Automatic Timestamps**: Track all changes

## 🎯 Alert Types

| Alert Type | Severity | Description |
|------------|----------|-------------|
| `usb_connection` | Medium | USB device connected |
| `restricted_access` | High | Attempted access to restricted files |
| `behavioral_anomaly` | Variable | Unusual user behavior detected |
| `network_spike` | High | Large data transfer detected |
| `failed_login_spike` | Critical | Multiple failed login attempts |

## 🔧 Configuration Options

### AI Model Settings
```python
MODEL_CONFIG = {
    'anomaly_threshold': 0.7,      # Sensitivity (0-1)
    'learning_period_days': 7,     # Days to learn behavior
    'retrain_interval_hours': 24,  # Model update frequency
    'feature_window_size': 10      # Analysis window
}
```

### Alert Settings
```python
ALERT_CONFIG = {
    'max_failed_logins': 5,           # Failed login threshold
    'network_spike_threshold': 1000000, # Bytes
    'file_access_spike_threshold': 50,   # Files per day
    'retention_days': 90              # Alert retention
}
```

## 🧪 Testing Features

### Built-in Test Functions
- **USB Test**: Simulates USB device connection
- **Restricted Access Test**: Simulates blocked file access
- **Behavioral Anomaly**: Triggers AI detection
- **Network Spike**: Tests large data transfer alerts

### API Endpoints
```
GET  /api/alerts              # Get recent alerts
GET  /api/alert_stats         # Get alert statistics
POST /api/acknowledge_alert   # Acknowledge alert
GET  /api/test_usb           # Test USB alert
GET  /api/test_restricted_access # Test file access alert
```

## 🔒 Security Features

### Authentication
- **Secure Login**: bcrypt password hashing
- **Session Management**: Flask sessions with CSRF protection
- **Role-based Access**: Admin/Manager/Employee roles

### Monitoring
- **Real-time File Monitoring**: Watchdog library
- **USB Detection**: Windows API integration
- **Process Monitoring**: psutil integration
- **Network Analysis**: Traffic pattern detection

## 📈 Performance Optimization

### Database Optimization
- **Indexed Queries**: Fast alert and activity lookups
- **Data Retention**: Automatic cleanup of old records
- **Connection Pooling**: Efficient database connections

### AI Optimization
- **Incremental Learning**: Updates models without full retraining
- **Feature Engineering**: Optimized behavioral features
- **Scalable Architecture**: Handles multiple users efficiently

## 🚨 Alert Workflow

1. **Detection**: System monitors activities in real-time
2. **Analysis**: AI analyzes behavior against learned baselines
3. **Scoring**: Assigns anomaly scores (0-1)
4. **Alerting**: Creates alerts above threshold
5. **Dashboard**: Displays alerts with severity levels
6. **Response**: Security team acknowledges and investigates

## 🔄 Continuous Learning

The system continuously learns and adapts:
- **Daily Baseline Updates**: Refines user behavior models
- **Pattern Recognition**: Identifies new threat patterns
- **False Positive Reduction**: Improves accuracy over time
- **Adaptive Thresholds**: Adjusts sensitivity based on environment

## 🛡️ Compliance & Privacy

### Data Protection
- **No Real PII**: All data is synthetic or anonymized
- **Secure Storage**: Encrypted database connections
- **Access Logging**: All system access is logged
- **Data Retention**: Configurable retention policies

### Compliance Ready
- **Audit Trails**: Complete activity logging
- **Role Separation**: Different access levels
- **Incident Response**: Built-in alert management
- **Reporting**: Exportable security reports

## 🚀 Getting Started Checklist

- [ ] Install MySQL and create database
- [ ] Install Python dependencies
- [ ] Configure database connection
- [ ] Run the application
- [ ] Login with default credentials
- [ ] Test USB and file access alerts
- [ ] Start real-time monitoring
- [ ] Review dashboard and alerts

## 📞 Support & Maintenance

### Monitoring Health
- Check logs in `logs/` directory
- Monitor database performance
- Review alert patterns
- Update AI models regularly

### Troubleshooting
- Verify database connection
- Check file permissions
- Ensure USB monitoring works
- Test alert generation

---

**🔐 Security Notice**: This system is designed for authorized security monitoring only. Ensure compliance with your organization's privacy policies and applicable laws.