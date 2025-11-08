from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

class PredictionRequest(BaseModel):
    timestamp: str
    method: str
    path: str
    query: str
    user_agent: str
    ip: str
    country: str
    referer: str
    content_length: int
    request_size: int
    attack_type: str = "Normal"
    is_attack: bool = False
    response_time: int = 0

class PredictionResponse(BaseModel):
    is_anomaly: bool
    confidence: float
    threat_type: str
    anomaly_score: float

@router.post("/predict", response_model=PredictionResponse)
async def predict_threat(request: PredictionRequest):
    """Real-time ML threat prediction for Cloudflare Worker"""
    
    try:
        from app.services.ml_service import ml_service
        
        # Convert web request to ML format
        ml_event = {
            "timestamp": request.timestamp,
            "src_ip": request.ip,
            "dst_ip": "nitedu.in",
            "src_port": 443,
            "dst_port": 80,
            "protocol": "HTTP",
            "packet_count": 1,
            "byte_count": request.content_length,
            "duration": request.response_time / 1000.0,
            "method": request.method,
            "path": request.path,
            "user_agent": request.user_agent,
            "country": request.country,
            "request_size": request.request_size
        }
        
        # Get ML prediction
        result = await ml_service.detect_anomaly(ml_event)
        
        # Determine threat type
        threat_type = "Unknown"
        if result['is_anomaly']:
            if "sql" in request.path.lower() or "union" in request.query.lower():
                threat_type = "SQL Injection"
            elif "script" in request.query.lower():
                threat_type = "XSS Attack"
            elif "bot" in request.user_agent.lower():
                threat_type = "Bot Attack"
            else:
                threat_type = "Behavioral Anomaly"
        
        return PredictionResponse(
            is_anomaly=result['is_anomaly'],
            confidence=result['confidence'],
            threat_type=threat_type,
            anomaly_score=result['anomaly_score']
        )
        
    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        # Fallback to safe response
        return PredictionResponse(
            is_anomaly=False,
            confidence=0.0,
            threat_type="Normal",
            anomaly_score=0.0
        )