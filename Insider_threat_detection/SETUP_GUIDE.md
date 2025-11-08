# Real-time Insider Threat Detection System - Setup Guide

## 🎯 System Overview

Complete real-time monitoring system with:
- **Real-time USB/Device Detection** (WMI-based)
- **File Access Monitoring** (Watchdog library)
- **Network Activity Tracking** (psutil)
- **ML-based Behavioral Anomaly Detection** (Isolation Forest)
- **Live Dashboard with WebSocket Alerts** (Flask-SocketIO)
- **MySQL Database Integration**
- **Windows Autostart Service**

---

## 📋 Prerequisites

1. **Python 3.8+** installed
2. **MySQL Server** installed and running
3. **Windows OS** (for WMI and autostart features)
4. **Administrator privileges** (for system monitoring)

---

## 🚀 Installation Steps

### Step 1: Install Python Dependencies

```bash
pip install -r requirements_realtime.txt
```

### Step 2: Setup MySQL Database

1. Start MySQL server
2. Run the database schema:

```bash
mysql -u root -p < database_schema.sql
```

This creates:
- `InsiderThreatDB` database
- Tables: `organization`, `user_activity`, `task_insights`, `alert_logs`, `restricted_files`, `device_whitelist`
- Default admin account: `admin / admin123`

### Step 3: Configure MySQL Password

Edit `start_system.bat` and set your MySQL password:

```batch
set MYSQL_PASSWORD=your_actual_password
```

### Step 4: Train ML Model (Optional)

If you have existing data, train the model:

```bash
python train_pipeline.py
```

This creates `models/isolation_forest.pkl` for behavioral detection.

---

## 🎮 Running the System

### Manual Start

Run the batch file:

```bash
start_system.bat
```

This starts 3 components:
1. **Flask Dashboard** (Port 5000)
2. **Real-time Monitor** (USB, Files, Network)
3. **Behavioral Detector** (ML-based anomaly detection)

### Configure Autostart (Optional)

To run on Windows startup:

```bash
setup_autostart.bat
```

---

## 🌐 Accessing the Dashboard

1. Open browser: `http://localhost:5000`
2. Login with:
   - **Username**: `admin`
   - **Password**: `admin123`

### Dashboard Features

- **Real-time Statistics**: Active users, pending alerts, critical threats
- **Live Alert Stream**: WebSocket-based instant notifications
- **Interactive Charts**: Severity distribution, daily trends
- **Alert Management**: Acknowledge alerts, mark as Malicious/Negligent
- **Role-based Access**: Admin (all orgs) vs Organization (own data)

---

## 🔧 System Components

### 1. Real-time Monitor (`realtime_monitor.py`)

**Monitors:**
- USB device connections (via WMI)
- File access to restricted paths (via Watchdog)
- Network connections to foreign IPs

**Triggers alerts for:**
- USB insertions
- Restricted file access
- Suspicious network activity

**Run standalone:**
```bash
python realtime_monitor.py
```

### 2. Behavioral Detector (`behavioral_detector.py`)

**Analyzes:**
- Daily user activity patterns
- Off-hours activity
- Data transfer volumes
- Failed login attempts
- USB usage frequency

**Uses ML model** (Isolation Forest) to detect deviations from normal behavior.

**Run standalone:**
```bash
python behavioral_detector.py
```

### 3. Flask Dashboard (`realtime_dashboard.py`)

**Provides:**
- Web-based admin interface
- Real-time alert notifications (Flask-SocketIO)
- REST APIs for event logging
- Role-based access control

**Run standalone:**
```bash
python realtime_dashboard.py your_mysql_password
```

---

## 📡 REST API Endpoints

### POST `/api/log_event`
Log a new system event
```json
{
  "ip": "172.16.111.80",
  "event_type": "file_access",
  "file_name": "confidential.docx",
  "file_path": "C:\\confidential\\confidential.docx"
}
```

### GET `/api/get_alerts`
Fetch recent alerts (filtered by role)

### POST `/api/trigger_alert`
Trigger real-time WebSocket alert
```json
{
  "alert_id": 123
}
```

### POST `/api/acknowledge_alert`
Acknowledge an alert
```json
{
  "alert_id": 123,
  "feedback": "Malicious"
}
```

### GET `/api/get_statistics`
Get dashboard statistics (charts data)

### GET `/api/get_user_activity?ip=172.16.111.80`
Get activity logs for specific user

---

## 🗄️ Database Schema

### `organization`
- Primary Key: `IPAddress`
- Stores user credentials and roles (Admin/Organization)

### `user_activity`
- Logs all system events (file access, USB, network, logins)
- Foreign Key: `IPAddress` → `organization`

### `task_insights`
- Daily behavioral patterns with anomaly scores
- Unique constraint: `(IPAddress, Date)`

### `alert_logs`
- Real-time alerts with severity levels
- Admin feedback: Pending/Malicious/Negligent

### `restricted_files`
- Paths that trigger alerts when accessed

### `device_whitelist`
- Approved devices per user

---

## 🔐 Adding New Users

```sql
INSERT INTO organization (IPAddress, OrgName, Username, Password, Role, Department)
VALUES ('172.16.111.80', 'Engineering Dept', 'john_doe', 'password123', 'Organization', 'Engineering');
```

---

## 🛡️ Adding Restricted Files

```sql
INSERT INTO restricted_files (FilePath, Description)
VALUES ('C:\\confidential\\', 'Confidential Documents');
```

---

## 🎨 Customization

### Change Monitoring Interval

**Real-time Monitor** (default: 2 seconds):
```python
time.sleep(2)  # Line in realtime_monitor.py
```

**Behavioral Detector** (default: 5 minutes):
```python
detector.run_continuous(interval=300)  # Line in behavioral_detector.py
```

### Adjust Anomaly Threshold

In `behavioral_detector.py`:
```python
if anomaly_score > 0.8:  # Critical
    risk_level = 'Critical'
elif anomaly_score > 0.6:  # High
    risk_level = 'High'
```

### Add Custom Alert Rules

In `realtime_monitor.py`, add to `FileAccessMonitor.check_file_access()`:
```python
if 'secret' in file_path.lower():
    self.db.create_alert(self.ip, 'custom_rule', 'High', 'Secret file accessed')
```

---

## 🐛 Troubleshooting

### Issue: "Database connection failed"
- Ensure MySQL is running: `net start MySQL80`
- Check credentials in `start_system.bat`

### Issue: "WMI access denied"
- Run Command Prompt as Administrator
- Check Windows Management Instrumentation service is running

### Issue: "Port 5000 already in use"
- Change port in `realtime_dashboard.py`:
  ```python
  socketio.run(app, port=5001)
  ```

### Issue: "No alerts appearing"
- Check if monitor is running
- Verify MySQL connection
- Check browser console for WebSocket errors

### Issue: "Model not found"
- Train model first: `python train_pipeline.py`
- Or system will use default Isolation Forest

---

## 📊 Testing the System

### Test USB Detection
1. Insert USB device or connect phone
2. Check dashboard for alert
3. Verify entry in `alert_logs` table

### Test File Access Monitoring
1. Create test file: `C:\confidential\test.txt`
2. Open/modify the file
3. Check dashboard for alert

### Test Behavioral Anomaly
1. Generate unusual activity (many file accesses at night)
2. Wait for detector cycle (5 minutes)
3. Check for behavioral anomaly alert

---

## 🔄 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Windows System                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐      │
│  │   USB    │  │  Files   │  │  Network         │      │
│  └────┬─────┘  └────┬─────┘  └────┬─────────────┘      │
└───────┼─────────────┼─────────────┼────────────────────┘
        │             │             │
        ▼             ▼             ▼
┌─────────────────────────────────────────────────────────┐
│              Real-time Monitor (WMI/Watchdog)           │
│                         ↓                                │
│                   MySQL Database                         │
│                         ↓                                │
│              Behavioral Detector (ML)                    │
│                         ↓                                │
│              Flask Dashboard (WebSocket)                 │
└─────────────────────────────────────────────────────────┘
                          ↓
                    Admin Browser
```

---

## 📝 Project Structure

```
New_Model/
├── realtime_dashboard.py      # Flask app with SocketIO
├── realtime_monitor.py         # System monitoring service
├── behavioral_detector.py      # ML-based anomaly detection
├── database_schema.sql         # MySQL schema
├── start_system.bat            # Startup script
├── setup_autostart.bat         # Autostart configuration
├── requirements_realtime.txt   # Python dependencies
├── templates/
│   ├── login.html              # Login page
│   └── realtime_dashboard.html # Main dashboard
└── models/
    └── isolation_forest.pkl    # Trained ML model
```

---

## 🎓 For Final Year Project

### Key Features to Highlight

1. **Real-time Detection**: Sub-second alert generation
2. **Multi-layered Approach**: Rule-based + ML-based detection
3. **Scalable Architecture**: Modular components, REST APIs
4. **Production-ready**: Database persistence, role-based access
5. **User-friendly**: Interactive dashboard with live updates

### Demo Scenarios

1. **USB Exfiltration**: Connect USB → Instant alert
2. **Unauthorized Access**: Access restricted file → Alert
3. **Behavioral Anomaly**: Unusual activity pattern → ML alert
4. **Admin Response**: Acknowledge alert, mark as Malicious

---

## 📞 Support

For issues or questions, check:
- MySQL logs: `C:\ProgramData\MySQL\MySQL Server 8.0\Data\`
- Python errors: Check command prompt windows
- Dashboard logs: Browser console (F12)

---

## ✅ Quick Start Checklist

- [ ] MySQL installed and running
- [ ] Python 3.8+ installed
- [ ] Dependencies installed (`pip install -r requirements_realtime.txt`)
- [ ] Database created (`mysql < database_schema.sql`)
- [ ] MySQL password set in `start_system.bat`
- [ ] Run `start_system.bat`
- [ ] Access `http://localhost:5000`
- [ ] Login with `admin / admin123`
- [ ] Test USB detection
- [ ] Configure autostart (optional)

---

**System Status**: ✅ Production Ready
**Last Updated**: 2025
**Version**: 1.0
