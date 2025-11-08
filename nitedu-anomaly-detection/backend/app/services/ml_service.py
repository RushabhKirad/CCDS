import asyncio
import logging
from pathlib import Path
from typing import Dict, Any
import numpy as np
from datetime import datetime

logger = logging.getLogger(__name__)

class MLAnomalyService:
    def __init__(self):
        self.detector = None
        self.is_initialized = False
        
    async def initialize(self):
        """Initialize ML models"""
        try:
            # Check if models exist
            models_dir = Path("data/models")
            if not models_dir.exists():
                logger.warning("Models directory not found, using rule-based detection")
                self.is_initialized = True
                return True
                
            # Try to load models
            try:
                from ml.models.ensemble_detector import EnsembleAnomalyDetector
                from ml.training.real_data_trainer import RealDataTrainer
                
                # Try to load existing real data model or train new one
                try:
                    trainer = RealDataTrainer()
                    self.detector = trainer.train_on_real_data(sample_size=3000)
                except Exception as train_error:
                    logger.warning(f"Failed to train on real data: {train_error}")
                    self.detector = None
                    logger.info("✅ ML models loaded successfully")
                else:
                    logger.warning("Model files not found, using rule-based detection")
                    
            except Exception as e:
                logger.warning(f"Failed to load ML models: {e}, using rule-based detection")
                
            self.is_initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize ML service: {e}")
            return False
    
    async def detect_anomaly(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomaly in event data"""
        
        if not self.is_initialized:
            await self.initialize()
        
        # Generate event ID
        event_id = event_data.get('id', f"evt_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        try:
            # Use ML model if available
            if self.detector:
                # Convert event to feature format
                from ml.preprocessing.feature_extractor import NetworkFeatureExtractor
                extractor = NetworkFeatureExtractor()
                features = extractor.extract_features([event_data])
                sequences, aggregated = extractor.create_sequences(features)
                
                results = self.detector.predict_anomalies(sequences, aggregated)
                
                return {
                    'event_id': event_id,
                    'timestamp': datetime.now(),
                    'is_anomaly': bool(results['ensemble_anomalies'][0]),
                    'anomaly_score': float(results['ensemble_scores'][0]),
                    'confidence': float(results['ensemble_scores'][0]),
                    'reason': 'ML ensemble detection',
                    'model_scores': {
                        'ensemble_score': float(results['ensemble_scores'][0]),
                        'hybrid_score': float(results['hybrid_scores'][0]),
                        'transformer_score': float(results['transformer_scores'][0]),
                        'isolation_score': float(results['isolation_scores'][0])
                    },
                    'event_details': event_data
                }
            else:
                # Fallback to rule-based detection
                return await self._rule_based_detection(event_data, event_id)
                
        except Exception as e:
            logger.error(f"ML detection failed: {e}, falling back to rules")
            return await self._rule_based_detection(event_data, event_id)
    
    async def _rule_based_detection(self, event_data: Dict[str, Any], event_id: str) -> Dict[str, Any]:
        """Rule-based anomaly detection fallback"""
        
        anomaly_score = 0.0
        reasons = []
        
        # Check for suspicious ports
        dst_port = event_data.get('dst_port', 80)
        if dst_port in [22, 23, 135, 139, 445, 1433, 3389]:
            anomaly_score += 0.3
            reasons.append(f"Suspicious destination port: {dst_port}")
        
        # Check for unusual packet counts
        packet_count = event_data.get('packet_count', 1)
        if packet_count > 100:
            anomaly_score += 0.2
            reasons.append(f"High packet count: {packet_count}")
        
        # Check for large data transfers
        byte_count = event_data.get('byte_count', 0)
        if byte_count > 10000:
            anomaly_score += 0.2
            reasons.append(f"Large data transfer: {byte_count} bytes")
        
        # Check for long duration connections
        duration = event_data.get('duration', 0.1)
        if duration > 10.0:
            anomaly_score += 0.2
            reasons.append(f"Long connection duration: {duration}s")
        
        # Check for suspicious source ports
        src_port = event_data.get('src_port', 80)
        if src_port in [1337, 31337, 4444, 6666]:
            anomaly_score += 0.4
            reasons.append(f"Suspicious source port: {src_port}")
        
        # Determine if anomaly
        is_anomaly = anomaly_score >= 0.5
        confidence = min(anomaly_score, 1.0)
        
        return {
            'event_id': event_id,
            'timestamp': datetime.now(),
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'confidence': confidence,
            'reason': '; '.join(reasons) if reasons else 'Normal traffic pattern',
            'model_scores': {
                'rule_based_score': anomaly_score,
                'lstm_score': 0.0,
                'isolation_score': 0.0,
                'hybrid_score': anomaly_score
            },
            'event_details': event_data
        }

# Global ML service instance
ml_service = MLAnomalyService()