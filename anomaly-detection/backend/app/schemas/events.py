from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any

class NetworkEventCreate(BaseModel):
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., ge=1, le=65535)
    dst_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(..., description="Protocol (tcp, udp, icmp, etc.)")
    packet_count: int = Field(..., ge=1)
    byte_count: int = Field(..., ge=1)
    duration: float = Field(..., ge=0.0)
    timestamp: Optional[datetime] = None
    raw_data: Optional[Dict[str, Any]] = None

class NetworkEventResponse(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    duration: float
    created_at: datetime

    class Config:
        from_attributes = True

class AnomalyAlertResponse(BaseModel):
    id: int
    event_id: str
    timestamp: datetime
    anomaly_score: float
    confidence: float
    is_anomaly: bool
    reason: str
    lstm_score: float
    isolation_score: float
    hybrid_score: float
    event_details: Dict[str, Any]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

class IngestionResponse(BaseModel):
    success: bool
    event_id: str
    message: str
    anomaly_detected: bool
    anomaly_score: Optional[float] = None