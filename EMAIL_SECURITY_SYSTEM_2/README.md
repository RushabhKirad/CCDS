# Email Security System

AI-powered email security module with phishing detection for Cyber Defence System integration.

## 🚀 Quick Start

```bash
pip install -r requirements.txt
python run.py
```

Access: http://localhost:5000 (admin/admin123)

## ✨ Features

- **AI Phishing Detection**: 5 ML models, 99.8% accuracy
- **Multi-User Support**: Gmail integration per user
- **Encryption**: Fernet-based credential encryption
- **RESTful API**: Integration-ready endpoints
- **Real-time Analysis**: Instant threat detection

## 🔌 Integration

**For Cyber Defence System integration**, see **`INTEGRATION_README.md`**

### Quick Integration
```python
from email_security_module import create_module

module = create_module()
result = module.analyze_email(email_data)
```

## ⚙️ Configuration

Edit `.env`:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=email_security_system
```

## 📁 Structure

```
email-security-system/
├── app.py                      # Flask application
├── run.py                      # Entry point
├── email_security_module.py    # Integration interface
├── api_routes.py               # REST API
├── hybrid_analysis.py          # ML engine (5 models)
├── backend/                    # Core logic
├── frontend/                   # Web UI
└── models/                     # Pre-trained models
```

## 🔧 API Endpoints

- `POST /email-security/api/v1/analyze` - Analyze email
- `GET /email-security/api/v1/threats` - Get threats
- `GET /email-security/api/v1/statistics` - Statistics
- `GET /email-security/api/v1/health` - Health check

## 📚 Documentation

- **`INTEGRATION_README.md`** - Integration guide for team
- `docs/DEPLOYMENT.md` - Deployment instructions
- `docs/PRODUCTION_READY.md` - Production features

## 📞 Support

**Developer**: Rushabh Kirad  
**Email**: rushabhkirad@gmail.com  
**Version**: 1.0.0