# 🗄️ MySQL Database Setup Guide

## 📋 Prerequisites
1. **Install MySQL**: Download from https://dev.mysql.com/downloads/mysql/
2. **Install Node.js**: Download from https://nodejs.org/

## 🚀 Setup Steps

### 1. Create Database
```sql
-- Open MySQL Command Line or MySQL Workbench
-- Run the database.sql file:
source C:/Users/samya/Desktop/Cognitive-Cyber-Defense-System/backend/database.sql
```

### 2. Configure Database Connection
Edit `backend/server.js` line 13-17:
```javascript
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'YOUR_MYSQL_PASSWORD', // Add your MySQL password here
    database: 'cyber_defense_db'
});
```

### 3. Start Backend Server
```bash
# Navigate to backend folder
cd backend

# Install dependencies
npm install

# Start server
npm start
```

### 4. Test Login System
1. **Open**: `frontend/landing-page/index.html`
2. **Click**: "Sign Up" button
3. **Create**: New account with valid email
4. **Login**: Use created credentials

## ✅ Expected Results
- ✅ Backend server runs on http://localhost:5000
- ✅ Database stores user accounts securely
- ✅ Passwords are hashed with bcrypt
- ✅ JWT tokens for authentication
- ✅ Login/Signup works from frontend

## 🔧 Troubleshooting
- **MySQL Connection Error**: Check MySQL service is running
- **Port 5000 in use**: Change PORT in server.js
- **CORS Error**: Backend handles CORS automatically