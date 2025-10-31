# Email Security System - Deployment Guide

## Quick Start

### 1. Install System
```bash
pip install -r requirements.txt
```

### 2. Configure Database
Update `.env` file with your database settings:
```env
DB_HOST=your_database_host
DB_USER=email_security
DB_PASSWORD=secure_password_123
DB_NAME=email_security_system
```

### 3. Run Application
```bash
python run.py
```

## Production Deployment

### Using Docker (Recommended)
```bash
docker build -t email-security-system .
docker run -p 5000:5000 email-security-system
```

### Using Gunicorn
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Using systemd (Linux)
Create `/etc/systemd/system/email-security.service`:
```ini
[Unit]
Description=Email Security System
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/email-security-system
Environment=PATH=/path/to/venv/bin
ExecStart=/path/to/venv/bin/python run.py
Restart=always

[Install]
WantedBy=multi-user.target
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Environment (development/production) | development |
| `DB_HOST` | Database host | localhost |
| `DB_USER` | Database user | email_security |
| `DB_PASSWORD` | Database password | secure_password_123 |
| `DB_NAME` | Database name | email_security_system |
| `PORT` | Application port | 5000 |
| `HOST` | Application host | 0.0.0.0 |

## Integration with Main Project

### As Microservice
```python
# Import the Flask app
from email_security_system.app import app as email_security_app

# Mount as blueprint
main_app.register_blueprint(email_security_app, url_prefix='/email-security')
```

### As Standalone Service
Run on separate port and use API endpoints:
- `POST /analyze_email` - Analyze email content
- `GET /dashboard` - Email dashboard
- `POST /fetch_emails` - Fetch user emails

## API Endpoints

### Authentication
- `POST /` - Login
- `POST /register` - Register user
- `GET /logout` - Logout

### Email Management
- `GET /dashboard` - Email dashboard
- `GET /email/<id>` - View email
- `POST /fetch_emails` - Fetch emails
- `POST /analyze_email` - Analyze email

### Admin
- `GET /admin/backend_monitor` - System monitoring
- `GET /show_calculations` - PQC calculations

## Security Features

- Post-Quantum Cryptography (PQC) for credential encryption
- User isolation at database level
- Session-based authentication
- SQL injection protection
- XSS protection via Flask templates

## Monitoring

- Application logs in `/logs/app.log`
- Database operation logs in `logs` table
- PQC operation tracking
- Real-time system monitoring for admins