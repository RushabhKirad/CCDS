from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import json
import sys
import os
import torch
import joblib
import numpy as np
from datetime import datetime
import logging
import asyncio
from typing import List
try:
    from .database import SecurityDatabase
except ImportError:
    try:
        from database import SecurityDatabase
    except ImportError:
        # Fallback to in-memory if database fails
        SecurityDatabase = None
        print("[WARN] Database module not found, using in-memory storage")

# Add parent directory to path to import our ML modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append('/opt/render/project/src')

try:
    from advanced_feature_engineering import AdvancedFeatureExtractor
    from advanced_inference_engine import AdvancedInferenceEngine
    ML_IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import ML modules: {e}")
    print("Falling back to basic detection")
    ML_IMPORTS_AVAILABLE = False

# Whitelist paths to skip detection (reduces false positives)
WHITELIST_PATHS = ['/', '/about', '/contact', '/home', '/images/', '/css/', '/js/', '/favicon.ico', '/robots.txt', '/sitemap.xml']

# Global ML components
class MLState:
    def __init__(self):
        self.engine = None
        self.feature_extractor = None
        self.available = False

ml_state = MLState()

# Initialize SQLite Database or fallback to in-memory
if SecurityDatabase:
    db = SecurityDatabase()
    print("[OK] Using SQLite database")
else:
    # Fallback to in-memory storage
    db = None
    alerts_memory = []
    request_stats = {
        "total_requests": 0,
        "attack_requests": 0,
        "normal_requests": 0,
        "high_severity_attacks": 0,
        "last_updated": datetime.now().isoformat()
    }
    print("[WARN] Using in-memory storage fallback")

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"WebSocket connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"WebSocket disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message, default=str))
            except:
                disconnected.append(connection)
        
        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()

def load_ml_models():
    """Load trained ML models"""
    ml_state.available = False
    
    if not ML_IMPORTS_AVAILABLE:
        print("[WARN] ML modules not available, using fallback")
        return False
    
    try:
        # Try multiple possible paths for Render deployment
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'models'),
            '/opt/render/project/src/data/models',
            'data/models',
            './data/models'
        ]
        
        model_dir = None
        for path in possible_paths:
            if os.path.exists(path):
                model_dir = path
                break
        
        if not model_dir:
            print("[WARN] Model directory not found, using fallback")
            return False
        
        print(f"[INFO] Using model directory: {model_dir}")
        
        
        # Load feature extractor
        feature_extractor_path = os.path.join(model_dir, 'advanced_feature_extractor.joblib')
        if os.path.exists(feature_extractor_path):
            ml_state.feature_extractor = joblib.load(feature_extractor_path)
            print("[OK] Feature extractor loaded")
        
        # Load ML inference engine
        model_path = os.path.join(model_dir, 'advanced_ensemble_model.pth')
        metadata_path = os.path.join(model_dir, 'advanced_model_metadata.joblib')
        
        if os.path.exists(model_path) and os.path.exists(metadata_path):
            ml_state.engine = AdvancedInferenceEngine(model_dir)
            if ml_state.engine.load_models():
                ml_state.available = True
                print("[OK] Advanced ML models loaded successfully")
                return True
            else:
                print("[WARN] Failed to load ML models")
                return False
        else:
            print("[WARN] ML model files not found, using fallback detection")
            return False
            
    except Exception as e:
        print(f"[ERROR] Error loading ML models: {e}")
        ml_state.available = False
        return False

def is_whitelisted_path(path):
    """Check if path should skip detection"""
    path = path.lower().strip()
    
    # Exact matches for specific paths
    exact_matches = ['/', '/about', '/contact', '/home', '/favicon.ico', '/robots.txt', '/sitemap.xml']
    if path in exact_matches:
        return True
    
    # Prefix matches for resource directories (but not if they contain suspicious content)
    resource_prefixes = ['/images/', '/css/', '/js/', '/static/', '/assets/']
    for prefix in resource_prefixes:
        if path.startswith(prefix):
            # Check if the path contains suspicious patterns even in resource paths
            suspicious_patterns = ['<script', 'javascript:', 'alert(', "'", '"', '..', 'union', 'select']
            if not any(pattern in path for pattern in suspicious_patterns):
                return True
    
    return False

def fallback_detection(event_data):
    """Enhanced fallback rule-based detection with whitelist"""
    from urllib.parse import unquote
    
    path = unquote(str(event_data.get('path', ''))).lower()
    
    # Skip detection for whitelisted paths
    if is_whitelisted_path(path):
        return {
            "is_anomaly": False,
            "confidence": 0.0,
            "attack_type": "Normal (Whitelisted)",
            "method": "whitelist_skip"
        }
    
    score = 0.0
    query = unquote(str(event_data.get('query', ''))).lower()
    user_agent = str(event_data.get('user_agent', '')).lower()
    method = event_data.get('method', 'GET')
    
    # Combine path and query for comprehensive analysis
    full_payload = path + query
    
    # Enhanced detection patterns
    
    # Advanced Scanner Detection (check user-agent first)
    if any(pattern in user_agent for pattern in ['sqlmap', 'nikto', 'nmap', 'masscan', 'zap', 'burp', 'w3af', 'scanner']):
        score = 0.95
        attack_type = "Advanced Scanner"
    
    # SQL Injection Detection
    elif any(pattern in full_payload for pattern in ['union', 'select', 'drop', "' or '", "'=''", '--', 'insert', 'delete', 'update', 'information_schema']):
        score = 0.92
        attack_type = "SQL Injection"
    
    # XSS Detection
    elif any(pattern in full_payload for pattern in ['<script', 'javascript:', 'alert(', 'onerror=', '<iframe', 'onload=', 'onclick=']):
        score = 0.88
        attack_type = "XSS Attack"
    
    # Command Injection
    elif any(pattern in full_payload for pattern in ['|', '&&', ';', '$(', '`', 'cat ', 'ls ', 'wget ', 'curl ']):
        score = 0.90
        attack_type = "Command Injection"
    
    # Directory Traversal
    elif any(pattern in full_payload for pattern in ['../', '..\\', '%2e%2e', '%252e']):
        score = 0.85
        attack_type = "Directory Traversal"
    
    # Brute Force (login attempts)
    elif method == 'POST' and any(pattern in path for pattern in ['login', 'auth', 'signin', 'admin']):
        score = 0.70
        attack_type = "Brute Force"
    
    # Generic Bot (lower priority)
    elif any(pattern in user_agent for pattern in ['bot', 'crawler', 'spider', 'curl', 'python', 'wget']):
        score = 0.75
        attack_type = "Bot Traffic"
    
    else:
        attack_type = "Normal"
    
    # Debug output
    if score > 0.3:
        print(f"[DEBUG] Detection: {attack_type} (score: {score:.2f}) for path: {path}")
    
    return {
        "is_anomaly": score > 0.3,
        "confidence": min(score, 1.0),
        "attack_type": attack_type,
        "method": "enhanced_fallback_rules"
    }

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load ML models on startup"""
    print("[INFO] Starting ML model loading...")
    success = load_ml_models()
    print(f"[INFO] ML loading result: {success}")
    print(f"[INFO] ML available: {ml_state.available}")
    yield
    print("[INFO] Shutting down...")

app = FastAPI(
    title="Anomaly Detection System - ML Powered",
    description="Advanced ML anomaly detection for nitedu.in",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "Anomaly Detection System - ML Powered",
        "status": "operational",
        "version": "2.0.0",
        "ml_enabled": ml_state.available,
        "features": "Advanced ML Detection" if ml_state.available else "Rule-based Detection"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "service": "nitedu-protection-ml",
        "ml_status": "enabled" if ml_state.available else "fallback"
    }

@app.post("/api/v1/predict")
async def predict_anomaly(request: Request):
    """ML-powered anomaly prediction endpoint with whitelist filtering"""
    try:
        body = await request.body()
        event_data = json.loads(body) if body else {}
        
        # Add request metadata (decode URLs to catch encoded attacks)
        from urllib.parse import unquote
        
        event_data.update({
            "client_ip": request.client.host,
            "timestamp": int(datetime.now().timestamp()),
            "method": event_data.get("method", "GET"),
            "path": unquote(event_data.get("path", "/")),
            "query": unquote(event_data.get("query", "")),
            "user_agent": event_data.get("user_agent", ""),
            "headers": dict(request.headers)
        })
        
        # Check whitelist first - skip detection for common paths
        if is_whitelisted_path(event_data["path"]):
            # Always update request statistics
            db.increment_stats(requests=1)
            
            return {
                "event_id": f"whitelist_{int(datetime.now().timestamp())}",
                "is_anomaly": False,
                "confidence": 0.0,
                "attack_type": "Normal (Whitelisted)",
                "method": "whitelist_skip",
                "source_ip": str(event_data.get("client_ip", "unknown"))
            }
        
        if ml_state.engine and ml_state.available:
            # Use advanced ML prediction
            try:
                result = ml_state.engine.predict_anomaly(event_data)
                response_data = {
                    "event_id": f"ml_{int(datetime.now().timestamp())}",
                    "is_anomaly": bool(result.get("is_anomaly", False)),
                    "confidence": float(result.get("confidence", 0.0)),
                    "attack_type": str(result.get("attack_type", "Unknown")),
                    "risk_score": float(result.get("risk_score", 0.0)),
                    "method": "advanced_ml",
                    "model_version": "2.0.0",
                    "inference_time_ms": int(result.get("inference_time_ms", 0)),
                    "model_scores": {k: float(v) for k, v in result.get("model_scores", {}).items()},
                    "source_ip": str(event_data.get("client_ip", "unknown"))
                }
            except Exception as e:
                print(f"ML prediction error: {e}")
                result = fallback_detection(event_data)
                response_data = {
                    "event_id": f"rule_{int(datetime.now().timestamp())}",
                    "is_anomaly": bool(result["is_anomaly"]),
                    "confidence": float(result["confidence"]),
                    "attack_type": str(result["attack_type"]),
                    "method": str(result["method"]),
                    "source_ip": str(event_data.get("client_ip", "unknown"))
                }
        else:
            # Use fallback detection
            result = fallback_detection(event_data)
            response_data = {
                "event_id": f"rule_{int(datetime.now().timestamp())}",
                "is_anomaly": bool(result["is_anomaly"]),
                "confidence": float(result["confidence"]),
                "attack_type": str(result["attack_type"]),
                "method": str(result["method"]),
                "source_ip": str(event_data.get("client_ip", "unknown"))
            }
        
        # Always update request statistics
        db.increment_stats(requests=1)
        
        # Store in database and broadcast if anomaly detected
        if response_data["is_anomaly"]:
            alert = {
                "id": response_data["event_id"],
                "timestamp": datetime.now().isoformat(),
                "attack_type": response_data["attack_type"],
                "confidence": response_data["confidence"],
                "source_ip": response_data["source_ip"],
                "method": response_data["method"],
                "path": event_data.get("path", "/"),
                "user_agent": event_data.get("user_agent", "")
            }
            
            # Store in database
            db.add_alert(alert)
            
            # Update statistics
            high_severity = 1 if response_data["confidence"] >= 0.8 else 0
            db.increment_stats(attacks=1, high_severity=high_severity)
            
            # Debug: Print alert being stored
            print(f"[DEBUG] Storing alert: {response_data['attack_type']} (confidence: {response_data['confidence']})")
            
            # Broadcast to dashboard via WebSocket
            await manager.broadcast({
                "type": "anomaly_alert",
                "data": alert
            })
        
        return response_data
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@app.post("/api/v1/ingest")
async def ingest_event(request: Request):
    """Legacy endpoint - redirects to ML prediction"""
    return await predict_anomaly(request)

@app.post("/api/v1/log-request")
async def log_request(request: Request):
    """Log all requests from Cloudflare Worker"""
    try:
        body = await request.body()
        request_data = json.loads(body) if body else {}
        
        # Log request to database
        db.add_request(request_data)
        
        # Update request statistics
        db.increment_stats(requests=1)
        
        # Check if this is an attack
        if request_data.get("is_attack", False):
            # Create alert for dashboard
            alert = {
                "id": f"cf_{int(datetime.now().timestamp())}_{datetime.now().microsecond}",
                "timestamp": datetime.now().isoformat(),
                "attack_type": request_data.get("attack_type", "Unknown Attack"),
                "confidence": 0.9,  # High confidence for rule-based detection
                "source_ip": request_data.get("ip", "unknown"),
                "method": "Cloudflare Worker",
                "path": request_data.get("path", "/"),
                "user_agent": request_data.get("user_agent", "")
            }
            
            # Store alert in database
            db.add_alert(alert)
            
            # Update attack statistics
            db.increment_stats(attacks=1, high_severity=1)
            
            # Broadcast real-time alert
            await manager.broadcast({
                "type": "anomaly_alert",
                "data": alert
            })
        
        # Get current stats for response
        current_stats = db.get_stats()
        
        # Broadcast traffic update every 10 requests
        if current_stats["total_requests"] % 10 == 0:
            await manager.broadcast({
                "type": "traffic_update",
                "data": {
                    "total_requests": current_stats["total_requests"],
                    "attack_requests": current_stats["attack_requests"],
                    "timestamp": datetime.now().isoformat()
                }
            })
        
        return {"status": "logged", "total_requests": current_stats["total_requests"]}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/v1/alerts")
async def get_alerts():
    """Get recent security alerts from database"""
    return db.get_alerts(limit=50)

@app.get("/api/v1/alerts/stats/summary")
async def get_alert_stats():
    """Get real-time statistics from database"""
    stats = db.get_stats()
    
    detection_rate = 0
    if stats["total_requests"] > 0:
        detection_rate = (stats["attack_requests"] / stats["total_requests"]) * 100
    
    alerts = db.get_alerts(limit=1000)  # Get all alerts for count
    
    return {
        "total_alerts": len(alerts),
        "high_severity_alerts": stats["high_severity_attacks"],
        "total_requests": stats["total_requests"],
        "attack_requests": stats["attack_requests"],
        "normal_requests": stats["normal_requests"],
        "detection_rate": round(detection_rate, 2),
        "alert_rate": stats["attack_requests"],
        "time_window_hours": 24,
        "last_updated": stats["last_updated"]
    }

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alerts"""
    await manager.connect(websocket)
    try:
        # Send initial stats from database
        current_stats = db.get_stats()
        await websocket.send_text(json.dumps({
            "type": "connection",
            "message": "Connected to real-time alerts",
            "stats": current_stats
        }))
        
        # Keep connection alive
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)

@app.get("/api/v1/status")
async def get_status():
    """Get system status and ML model info"""
    current_stats = db.get_stats()
    alerts = db.get_alerts(limit=1000)
    
    return {
        "system_status": "operational",
        "ml_models_loaded": ml_state.available,
        "feature_extractor_loaded": ml_state.feature_extractor is not None,
        "inference_engine_loaded": ml_state.engine is not None,
        "detection_method": "advanced_ml" if ml_state.available else "rule_based",
        "model_version": "2.0.0",
        "total_alerts_in_database": len(alerts),
        "websocket_connections": len(manager.active_connections),
        "request_stats": current_stats,
        "timestamp": datetime.now().isoformat()
    }