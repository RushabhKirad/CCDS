from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

class NetworkEvent(Base):
    __tablename__ = "network_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer, index=True)
    protocol = Column(String(10), index=True)
    packet_count = Column(Integer)
    byte_count = Column(Integer)
    duration = Column(Float)
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=func.now())

class AnomalyAlert(Base):
    __tablename__ = "anomaly_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(50), index=True)
    timestamp = Column(DateTime, index=True)
    anomaly_score = Column(Float)
    confidence = Column(Float)
    is_anomaly = Column(Boolean, default=False)
    reason = Column(Text)
    lstm_score = Column(Float)
    isolation_score = Column(Float)
    hybrid_score = Column(Float)
    event_details = Column(JSON)
    model_scores = Column(JSON)
    status = Column(String(20), default="new")  # new, reviewed, false_positive
    created_at = Column(DateTime, default=func.now())

class ProcessingWindow(Base):
    __tablename__ = "processing_windows"
    
    id = Column(Integer, primary_key=True, index=True)
    window_start = Column(DateTime, index=True)
    window_end = Column(DateTime, index=True)
    event_count = Column(Integer)
    anomaly_count = Column(Integer)
    avg_anomaly_score = Column(Float)
    processed_at = Column(DateTime, default=func.now())