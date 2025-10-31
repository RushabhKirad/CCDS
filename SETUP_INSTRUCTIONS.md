# 🛡️ Cognitive Cyber Defense System - Setup Instructions

## 📋 Prerequisites

1. **Python 3.8+** installed
2. **Node.js 14+** and npm installed  
3. **MySQL 8.0+** installed and running
4. **Git** (optional, for cloning)

## 🚀 Quick Setup (3 Steps)

### Step 1: Database Setup
1. Open **MySQL Workbench** or **MySQL Command Line**
2. Run the existing database.sql script:
   ```sql
   SOURCE backend/database.sql;
   ```
   This creates the cyber_defense_db database with users table

### Step 2: Start All Modules
Choose one of these methods:

**Method A: Python Script (Recommended)**
```bash
python run_all_modules.py
```

**Method B: Batch File (Windows)**
```bash
start_all_modules.bat
```

### Step 3: Access the System
- **Main System**: http://localhost:8080
- **Email Security**: http://localhost:5001  
- **Insider Threat**: http://localhost:5002
- **Anomaly Detection**: http://localhost:8001

## 🔐 Default Login Credentials

### Main System
- Create account via signup form

### Email Security System  
- **Username**: admin
- **Password**: admin123

### Insider Threat Detection
- **Username**: admin  
- **Password**: admin123
- **Test User**: testuser / test123

## 📊 Module Ports

| Module | Port | URL |
|--------|------|-----|
| Frontend | 8080 | http://localhost:8080 |
| Main Backend | 3000 | http://localhost:3000 |
| Email Security | 5001 | http://localhost:5001 |
| Insider Threat | 5002 | http://localhost:5002 |
| Anomaly Detection | 8001 | http://localhost:8001 |

## 🗄️ MySQL Database

- **cyber_defense_db** - Main system users and authentication

## 🔧 Manual Module Startup

If you need to start modules individually:

```bash
# Main Backend
cd backend
npm install && node server.js

# Email Security  
cd EMAIL_SECURITY_SYSTEM_2
pip install -r requirements.txt
python app.py

# Insider Threat
cd Insider_threat_detection  
pip install -r requirements_new.txt
python app.py --port=5002

# Anomaly Detection
cd nitedu-anomaly-detection
pip install -r requirements.txt
uvicorn backend.app.main_production:app --host 0.0.0.0 --port 8001

# Frontend
cd frontend/landing-page
python -m http.server 8080
```

## 🧪 Testing the Integration

1. Access http://localhost:8080
2. Sign up for a new account
3. Login and click on each module card
4. Verify all modules open in new tabs

## 🛠️ Troubleshooting

### Port Already in Use
```bash
# Windows - Kill process on port
netstat -ano | findstr :5001
taskkill /PID <PID> /F

# Linux/Mac - Kill process on port  
lsof -ti:5001 | xargs kill -9
```

### MySQL Connection Issues
- Ensure MySQL is running
- Check username/password in configuration files
- Verify databases were created successfully

### Module Not Starting
- Check if all dependencies are installed
- Verify Python/Node.js versions
- Check console output for error messages

## 📞 Support

For issues or questions:
- **Samyak**: Anomaly Detection System
- **Rushabh**: Email Security System  
- **Riddhi**: Insider Threat Detection

## 🎯 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Cognitive Cyber Defense System             │
├─────────────────────────────────────────────────────────────┤
│  Frontend (8080) → Main Backend (3000) → MySQL Databases   │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Email Sec   │  │ Insider     │  │ Anomaly Detection   │  │
│  │ (5001)      │  │ Threat      │  │ (8001)             │  │
│  │             │  │ (5002)      │  │                    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

🎉 **Your Cognitive Cyber Defense System is ready!**