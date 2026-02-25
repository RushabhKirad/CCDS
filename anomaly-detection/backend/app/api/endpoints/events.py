from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
import uuid
import logging

from app.core.database import get_db
from app.schemas.events import NetworkEventCreate, NetworkEventResponse, IngestionResponse
from app.models.database import NetworkEvent, AnomalyAlert

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/ingest", response_model=IngestionResponse)
async def ingest_event(event: NetworkEventCreate, db: Session = Depends(get_db)):
    """Ingest network event for anomaly detection"""
    
    # Generate event ID
    event_id = f"evt_{uuid.uuid4().hex[:8]}"
    
    # Create database record
    db_event = NetworkEvent(
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        src_port=event.src_port,
        dst_port=event.dst_port,
        protocol=event.protocol,
        packet_count=event.packet_count,
        byte_count=event.byte_count,
        duration=event.duration,
        timestamp=event.timestamp or datetime.utcnow(),
        raw_data=event.raw_data
    )
    
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    
    # Prepare event for ML processing
    ml_event = {
        "id": event_id,
        "db_id": db_event.id,
        "timestamp": db_event.timestamp.isoformat(),
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "packet_count": event.packet_count,
        "byte_count": event.byte_count,
        "duration": event.duration
    }
    
    # Process with ML service immediately
    try:
        from app.services.ml_service import ml_service
        
        # Run ML detection
        ml_result = await ml_service.detect_anomaly(ml_event)
        
        # Store alert if anomaly detected
        if ml_result['is_anomaly']:
            alert = AnomalyAlert(
                event_id=ml_result['event_id'],
                timestamp=ml_result['timestamp'],
                anomaly_score=ml_result['anomaly_score'],
                confidence=ml_result['confidence'],
                is_anomaly=ml_result['is_anomaly'],
                reason=ml_result['reason'],
                lstm_score=ml_result['model_scores'].get('lstm_score', 0.0),
                isolation_score=ml_result['model_scores'].get('isolation_score', 0.0),
                hybrid_score=ml_result['model_scores'].get('hybrid_score', 0.0),
                event_details=ml_result.get('event_details', {}),
                model_scores=ml_result['model_scores'],
                status="new"
            )
            
            db.add(alert)
            db.commit()
            logger.info(f"🚨 Anomaly detected: {ml_result['reason']}")
        
        return IngestionResponse(
            success=True,
            event_id=event_id,
            message="Event processed successfully",
            anomaly_detected=ml_result['is_anomaly'],
            anomaly_score=ml_result['anomaly_score']
        )
        
    except Exception as e:
        logger.error(f"ML processing failed: {e}")
        return IngestionResponse(
            success=True,
            event_id=event_id,
            message="Event ingested (ML processing failed)",
            anomaly_detected=False,
            anomaly_score=None
        )

@router.get("/events", response_model=List[NetworkEventResponse])
async def get_events(limit: int = 100, db: Session = Depends(get_db)):
    """Get recent network events"""
    events = db.query(NetworkEvent).order_by(NetworkEvent.created_at.desc()).limit(limit).all()
    return events