import numpy as np
import torch
from typing import Dict, List, Any, Optional
from collections import deque
import logging
import sys
import os

# Add parent directories to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from ml.models.hybrid_detector import HybridAnomalyDetector
from ml.preprocessing.feature_extractor import NetworkFeatureExtractor

logger = logging.getLogger(__name__)

class RealTimeAnomalyDetector:
    def __init__(self, lstm_model_path: str, isolation_model_path: str,
                 sequence_length: int = 10, buffer_size: int = 100):
        self.sequence_length = sequence_length
        self.buffer_size = buffer_size
        
        # Initialize components
        self.feature_extractor = NetworkFeatureExtractor()
        self.detector = HybridAnomalyDetector(sequence_length=sequence_length)
        
        # Load trained models
        self.detector.load_models(lstm_model_path, isolation_model_path)
        
        # Event buffer for sequence creation
        self.event_buffer = deque(maxlen=buffer_size)
        self.feature_buffer = deque(maxlen=buffer_size)
        
        logger.info("Real-time detector initialized")
    
    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single network event and return anomaly detection results"""
        
        # Extract features from the event
        features = self.feature_extractor.extract_features([event])
        feature_vector = features[0]
        
        # Add to buffers
        self.event_buffer.append(event)
        self.feature_buffer.append(feature_vector)
        
        # Check if we have enough data for sequence analysis
        if len(self.feature_buffer) < self.sequence_length:
            return {
                'event_id': event.get('id', 'unknown'),
                'timestamp': event.get('timestamp'),
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'reason': 'Insufficient data for analysis',
                'model_scores': {}
            }
        
        # Create sequence and aggregated features
        recent_features = np.array(list(self.feature_buffer)[-self.sequence_length:])
        sequence = recent_features.reshape(1, self.sequence_length, -1)
        
        # Aggregate features for Isolation Forest
        aggregated = np.concatenate([
            np.mean(recent_features, axis=0),
            np.std(recent_features, axis=0),
            np.max(recent_features, axis=0) - np.min(recent_features, axis=0)
        ]).reshape(1, -1)
        
        # Get predictions
        try:
            scores = self.detector.predict_anomaly_scores(sequence, aggregated)
            predictions = self.detector.predict_anomalies(sequence, aggregated, threshold=0.5)
            
            # Extract results
            hybrid_score = scores['hybrid_scores'][0]
            is_anomaly = predictions['hybrid_anomalies'][0] == 1
            
            # Calculate confidence based on score magnitude
            confidence = min(1.0, abs(hybrid_score - 0.5) * 2)
            
            # Determine primary reason for anomaly
            reason = self._determine_anomaly_reason(scores, predictions)
            
            result = {
                'event_id': event.get('id', 'unknown'),
                'timestamp': event.get('timestamp'),
                'is_anomaly': bool(is_anomaly),
                'anomaly_score': float(hybrid_score),
                'confidence': float(confidence),
                'reason': reason,
                'model_scores': {
                    'lstm_score': float(scores['lstm_normalized'][0]),
                    'isolation_score': float(scores['isolation_normalized'][0]),
                    'hybrid_score': float(hybrid_score)
                },
                'event_details': {
                    'src_ip': event.get('src_ip'),
                    'dst_ip': event.get('dst_ip'),
                    'dst_port': event.get('dst_port'),
                    'protocol': event.get('protocol'),
                    'byte_count': event.get('byte_count'),
                    'packet_count': event.get('packet_count')
                }
            }
            
            if is_anomaly:
                logger.warning(f"Anomaly detected: {result}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")
            return {
                'event_id': event.get('id', 'unknown'),
                'timestamp': event.get('timestamp'),
                'is_anomaly': False,
                'anomaly_score': 0.0,
                'confidence': 0.0,
                'reason': f'Processing error: {str(e)}',
                'model_scores': {}
            }
    
    def _determine_anomaly_reason(self, scores: Dict[str, np.ndarray], 
                                 predictions: Dict[str, np.ndarray]) -> str:
        """Determine the primary reason for anomaly detection"""
        lstm_anomaly = predictions['lstm_anomalies'][0] == 1
        isolation_anomaly = predictions['isolation_anomalies'][0] == 1
        
        lstm_score = scores['lstm_normalized'][0]
        isolation_score = scores['isolation_normalized'][0]
        
        if lstm_anomaly and isolation_anomaly:
            return "Both temporal pattern and feature outlier detected"
        elif lstm_anomaly:
            return f"Unusual temporal sequence pattern (score: {lstm_score:.3f})"
        elif isolation_anomaly:
            return f"Statistical outlier in features (score: {isolation_score:.3f})"
        elif scores['hybrid_scores'][0] > 0.5:
            return f"Combined anomaly score exceeded threshold"
        else:
            return "Normal traffic pattern"
    
    def process_batch(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of events"""
        results = []
        for event in events:
            result = self.process_event(event)
            results.append(result)
        return results
    
    def get_buffer_stats(self) -> Dict[str, Any]:
        """Get statistics about the current buffer state"""
        return {
            'buffer_size': len(self.event_buffer),
            'max_buffer_size': self.buffer_size,
            'sequence_length': self.sequence_length,
            'ready_for_analysis': len(self.feature_buffer) >= self.sequence_length
        }
    
    def clear_buffer(self):
        """Clear the event buffer"""
        self.event_buffer.clear()
        self.feature_buffer.clear()
        logger.info("Event buffer cleared")