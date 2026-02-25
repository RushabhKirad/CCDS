from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta

from app.core.database import get_db
from app.schemas.events import AnomalyAlertResponse
from app.models.database import AnomalyAlert

router = APIRouter()

@router.get("/alerts", response_model=List[AnomalyAlertResponse])
async def get_alerts(
    limit: int = 100,
    status: Optional[str] = None,
    min_score: Optional[float] = None,
    hours: Optional[int] = 24,
    db: Session = Depends(get_db)
):
    """Get anomaly alerts with filtering"""
    
    query = db.query(AnomalyAlert)
    
    # Filter by time window
    if hours:
        since = datetime.utcnow() - timedelta(hours=hours)
        query = query.filter(AnomalyAlert.created_at >= since)
    
    # Filter by status
    if status:
        query = query.filter(AnomalyAlert.status == status)
    
    # Filter by minimum score
    if min_score:
        query = query.filter(AnomalyAlert.anomaly_score >= min_score)
    
    alerts = query.order_by(AnomalyAlert.created_at.desc()).limit(limit).all()
    return alerts

@router.get("/alerts/{alert_id}", response_model=AnomalyAlertResponse)
async def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Get specific alert details"""
    alert = db.query(AnomalyAlert).filter(AnomalyAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.put("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: int, 
    status: str,
    db: Session = Depends(get_db)
):
    """Update alert status (reviewed, false_positive, etc.)"""
    
    valid_statuses = ["new", "reviewed", "false_positive", "confirmed"]
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    
    alert = db.query(AnomalyAlert).filter(AnomalyAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = status
    db.commit()
    
    return {"success": True, "message": f"Alert status updated to {status}"}

@router.get("/alerts/stats/summary")
async def get_alert_stats(hours: int = 24, db: Session = Depends(get_db)):
    """Get alert statistics summary"""
    
    since = datetime.utcnow() - timedelta(hours=hours)
    
    total_alerts = db.query(AnomalyAlert).filter(AnomalyAlert.created_at >= since).count()
    high_severity = db.query(AnomalyAlert).filter(
        AnomalyAlert.created_at >= since,
        AnomalyAlert.anomaly_score >= 0.8
    ).count()
    
    return {
        "total_alerts": total_alerts,
        "high_severity_alerts": high_severity,
        "time_window_hours": hours,
        "alert_rate": total_alerts / hours if hours > 0 else 0
    }