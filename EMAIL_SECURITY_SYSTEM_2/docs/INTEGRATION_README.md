# Email Security Module - Integration Guide

## 🎯 Overview
AI-powered email security module for Cyber Defence System integration with Insider Threat and Anomaly Detection modules.

**Features**: 5 ML models, 99.8% accuracy, RESTful API, Event-driven architecture

---

## 🚀 Quick Start

```bash
pip install -r requirements.txt
python run.py
```
Access: http://localhost:5000 (admin/admin123)

---

## 🔌 Integration Methods

### Method 1: Python Module (Recommended)
```python
from email_security_module import create_module

module = create_module()
result = module.analyze_email({
    'sender': 'test@example.com',
    'subject': 'Urgent: Verify Account',
    'body': 'Click here...',
    'urls': ['http://suspicious.com']
})

# Returns: {'is_threat': True, 'confidence': 0.95, 'severity': 'critical', ...}
```

### Method 2: REST API
```python
import requests

# Get token
response = requests.post('http://localhost:5000/email-security/api/v1/auth/token',
    json={'username': 'admin', 'password': 'admin123'})
token = response.json()['token']

# Analyze email
response = requests.post('http://localhost:5000/email-security/api/v1/analyze',
    headers={'Authorization': f'Bearer {token}'},
    json={'sender': 'test@example.com', 'subject': 'Test', 'body': 'Content'})
```

### Method 3: Event Bus
```python
from event_bus import subscribe

def handle_threat(event):
    print(f"Threat: {event['data']['threat_type']}")
    insider_threat_module.check_user(event['user_id'])

subscribe('email_security.threat_detected', handle_threat)
```

---

## 📡 API Endpoints

**Base URL**: `/email-security/api/v1`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/analyze` | POST | Analyze email for threats |
| `/threats` | GET | Get detected threats |
| `/statistics` | GET | Module statistics |
| `/health` | GET | Health check |
| `/auth/token` | POST | Generate JWT token |

---

## 🏗️ Architecture

```
cyber-defence-system/
├── modules/
│   ├── email_security/          # This module
│   ├── insider_threat/          # Your team
│   └── anomaly_detection/       # Your team
├── api_gateway/
└── dashboard/
```

### Integration Example
```python
# main.py
from email_security_module import create_module

email_module = create_module()
insider_threat = InsiderThreatModule()
anomaly_detection = AnomalyDetectionModule()

@app.route('/unified-analysis', methods=['POST'])
def unified_analysis():
    data = request.json
    
    email_result = email_module.analyze_email(data['email'])
    insider_result = insider_threat.check_user(data['user_id'])
    anomaly_result = anomaly_detection.detect(data['behavior'])
    
    return jsonify({
        'email_threat': email_result,
        'insider_threat': insider_result,
        'anomaly': anomaly_result
    })
```

---

## 📊 Module Interface

```python
module = create_module()

# Analyze email
result = module.analyze_email(email_data)

# Get statistics
stats = module.get_statistics(timeframe='24h')

# Get threats
threats = module.get_threats({'user_id': 123})

# Health check
health = module.health_check()
```

---

## 🔧 Configuration

Edit `.env`:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=email_security_system
```

---

## 📁 Key Files

| File | Purpose |
|------|---------|
| `email_security_module.py` | Main integration interface |
| `api_routes.py` | RESTful API endpoints |
| `hybrid_analysis.py` | ML analysis engine (5 models) |
| `app.py` | Flask application |
| `run.py` | Entry point |

---

## 🔐 Authentication

JWT token structure:
```json
{
  "user_id": 123,
  "username": "john.doe",
  "modules": ["email_security", "insider_threat"],
  "exp": 1730304201
}
```

---

## 📈 Response Format

```json
{
  "is_threat": true,
  "threat_type": "phishing",
  "confidence": 0.95,
  "severity": "critical",
  "indicators": ["suspicious_url", "urgent_language"],
  "recommended_action": "block_and_quarantine"
}
```

---

## 🧪 Testing

```python
from email_security_module import create_module

module = create_module()

# Test phishing detection
result = module.analyze_email({
    'sender': 'attacker@evil.com',
    'subject': 'URGENT: Verify Account',
    'body': 'Click here: http://phishing.com'
})

assert result['is_threat'] == True
print("✓ Integration working")
```

---

## 📞 Support

**Developer**: Rushabh Kirad  
**Email**: rushabhkirad@gmail.com

---

## ✅ Integration Checklist

- [ ] Install dependencies
- [ ] Configure database
- [ ] Test standalone module
- [ ] Choose integration method
- [ ] Implement in main system
- [ ] Create unified dashboard
- [ ] Deploy together
