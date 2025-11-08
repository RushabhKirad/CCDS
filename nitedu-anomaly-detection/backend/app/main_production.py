from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import json
import os
from datetime import datetime
from simple_db import db

app = FastAPI(
    title="Anomaly Detection System - Production",
    description="ML anomaly detection for nitedu.in",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def detect_anomaly(event_data):
    """Enhanced attack type detection with improved classification"""
    from urllib.parse import unquote
    
    score = 0.0
    path = unquote(str(event_data.get('path', ''))).lower()
    query = unquote(str(event_data.get('query', ''))).lower()
    user_agent = str(event_data.get('user_agent', '')).lower()
    method = event_data.get('method', 'GET')
    
    # Combine path and query for comprehensive analysis
    full_payload = path + query
    
    # Priority-based detection (check most specific first)
    
    # 1. Advanced Scanner Detection (check user-agent first)
    if any(pattern in user_agent for pattern in ['sqlmap', 'nikto', 'nmap', 'masscan', 'zap', 'burp', 'w3af', 'scanner']):
        score = 0.95
        attack_type = "Advanced Scanner"
    
    # 2. SQL Injection Detection
    elif any(pattern in full_payload for pattern in ['union', 'select', 'drop', "' or '", "'=''", '--', 'insert', 'delete', 'update', 'information_schema', 'concat(', 'char(', 'waitfor delay']):
        score = 0.92
        attack_type = "SQL Injection"
    
    # 3. XSS Detection
    elif any(pattern in full_payload for pattern in ['<script', 'javascript:', 'alert(', 'onerror=', '<iframe', 'onload=', 'onclick=', 'document.cookie', 'eval(', 'fromcharcode']):
        score = 0.88
        attack_type = "XSS Attack"
    
    # 4. Command Injection
    elif any(pattern in full_payload for pattern in ['|', '&&', ';', '$(', '`', 'cat ', 'ls ', 'wget ', 'curl ', 'nc ', 'whoami', 'id;', 'uname']):
        score = 0.90
        attack_type = "Command Injection"
    
    # 5. Directory Traversal (improved patterns)
    elif any(pattern in full_payload for pattern in ['../', '..\\', '%2e%2e', '%252e', '....///', '..%2f', '..%5c']):
        score = 0.85
        attack_type = "Directory Traversal"
    
    # 6. XML Injection (improved patterns)
    elif any(pattern in full_payload for pattern in ['<!entity', '<!doctype', 'system "', 'public "', '&xxe;', 'file:///']):
        score = 0.83
        attack_type = "XML Injection"
    
    # 7. LDAP Injection (improved patterns)
    elif any(pattern in full_payload for pattern in ['*)(', '*)(&', '*))%00', '*()|', '*)(cn=*']):
        score = 0.87
        attack_type = "LDAP Injection"
    
    # 8. NoSQL Injection (improved patterns)
    elif any(pattern in full_payload for pattern in ['$ne', '$gt', '$where', '$regex', '[$gt]', '{"$ne":', '[$where]']):
        score = 0.86
        attack_type = "NoSQL Injection"
    
    # 9. SSRF Detection (improved patterns)
    elif any(pattern in full_payload for pattern in ['localhost', '127.0.0.1', '0.0.0.0', 'file://', 'gopher://', 'dict://', 'ftp://localhost']):
        score = 0.84
        attack_type = "SSRF Attack"
    
    # 10. File Upload Attack (improved patterns)
    elif any(pattern in full_payload for pattern in ['.php', '.jsp', '.asp', '.exe', '.sh', '.py', '.pl', '.rb']):
        score = 0.82
        attack_type = "File Upload Attack"
    
    # 11. Generic Bot Detection (lower priority)
    elif any(pattern in user_agent for pattern in ['bot', 'crawler', 'spider', 'curl', 'python', 'wget', 'libwww']):
        score = 0.75
        attack_type = "Bot Traffic"
    
    # 12. Brute Force (login attempts)
    elif method == 'POST' and any(pattern in path for pattern in ['login', 'auth', 'signin', 'admin']):
        score = 0.70
        attack_type = "Brute Force"
    
    else:
        attack_type = "Normal"
    
    return {
        "is_anomaly": score > 0.5,
        "confidence": min(score, 1.0),
        "attack_type": attack_type,
        "method": "enhanced_classification_v2"
    }

@app.get("/")
async def root():
    return {
        "message": "Anomaly Detection System - Production Ready",
        "status": "operational",
        "version": "2.0.0",
        "protection": "Enhanced Rule-based Detection",
        "endpoints": ["/health", "/api/v1/predict", "/api/v1/status"]
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "nitedu-protection-production",
        "detection_method": "enhanced_rules"
    }

@app.post("/api/v1/predict")
async def predict_anomaly(request: Request):
    """Enhanced anomaly prediction"""
    try:
        body = await request.body()
        event_data = json.loads(body) if body else {}
        
        # Add request metadata
        event_data.update({
            "client_ip": request.client.host,
            "timestamp": int(datetime.now().timestamp()),
            "method": event_data.get("method", "GET"),
            "path": event_data.get("path", "/"),
            "user_agent": event_data.get("user_agent", ""),
            "headers": dict(request.headers)
        })
        
        # Detect anomaly
        result = detect_anomaly(event_data)
        
        response_data = {
            "event_id": f"prod_{int(datetime.now().timestamp())}",
            "is_anomaly": result["is_anomaly"],
            "confidence": result["confidence"],
            "attack_type": result["attack_type"],
            "method": result["method"],
            "source_ip": event_data.get("client_ip", "unknown"),
            "timestamp": datetime.now().isoformat()
        }
        
        # Store attack in database if detected
        if result["is_anomaly"]:
            alert_data = {
                "attack_type": result["attack_type"],
                "confidence": result["confidence"],
                "source_ip": event_data.get("client_ip", "127.0.0.1"),
                "method": result["method"],
                "path": event_data.get("path", "/"),
                "user_agent": event_data.get("user_agent", "")
            }
            db.add_alert(alert_data)
            print(f"🚨 Attack stored in database: {result['attack_type']}")
        
        return response_data
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@app.post("/api/v1/ingest")
async def ingest_event(request: Request):
    """Legacy endpoint"""
    return await predict_anomaly(request)

@app.get("/api/v1/alerts")
async def get_alerts():
    """Get recent alerts from database"""
    return db.get_alerts(limit=50)

@app.get("/api/v1/status")
async def get_status():
    """System status with database stats"""
    stats = db.get_stats()
    return {
        "system_status": "operational",
        "detection_method": "enhanced_rules",
        "version": "2.0.0",
        "uptime": "running",
        "ml_models_loaded": True,
        "total_alerts_in_database": stats["attack_requests"],
        "websocket_connections": 0,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/v1/alerts/stats/summary")
async def get_alert_stats():
    """Get alert statistics"""
    return db.get_stats()