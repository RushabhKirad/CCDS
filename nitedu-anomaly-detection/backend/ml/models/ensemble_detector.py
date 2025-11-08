import numpy as np
import torch
from typing import Dict, List
from .hybrid_detector import HybridAnomalyDetector
from .transformer_detector import TransformerAnomalyDetector
from .isolation_forest import IsolationForestDetector

class EnsembleAnomalyDetector:
    def __init__(self, sequence_length: int = 10, feature_dim: int = 10):
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        
        # Initialize multiple detectors
        self.hybrid_detector = HybridAnomalyDetector(
            sequence_length=sequence_length, feature_dim=feature_dim
        )
        self.transformer_detector = TransformerAnomalyDetector(
            input_dim=feature_dim, sequence_length=sequence_length
        )
        self.isolation_detector = IsolationForestDetector(contamination=0.05)
        
        self.is_fitted = False
        self.weights = {'hybrid': 0.3, 'transformer': 0.3, 'isolation': 0.4}
    
    def fit(self, sequences: np.ndarray, features: np.ndarray):
        # Train hybrid detector
        self.hybrid_detector.fit(sequences, features)
        
        # Train transformer
        self._train_transformer(sequences)
        
        # Train isolation forest
        self.isolation_detector.fit(features)
        
        self.is_fitted = True
        return self
    
    def _train_transformer(self, sequences: np.ndarray, epochs: int = 30):
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.transformer_detector.to(device)
        
        X_tensor = torch.FloatTensor(sequences).to(device)
        optimizer = torch.optim.Adam(self.transformer_detector.parameters(), lr=0.001)
        criterion = torch.nn.MSELoss()
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            reconstructed = self.transformer_detector(X_tensor)
            loss = criterion(reconstructed, X_tensor)
            loss.backward()
            optimizer.step()
    
    def predict_anomaly_scores(self, sequences: np.ndarray, features: np.ndarray) -> Dict:
        if not self.is_fitted:
            raise ValueError("Ensemble must be fitted first")
        
        # Get scores from each detector
        hybrid_results = self.hybrid_detector.predict_anomaly_scores(sequences, features)
        
        X_tensor = torch.FloatTensor(sequences)
        transformer_scores = self.transformer_detector.get_reconstruction_error(X_tensor).numpy()
        
        isolation_scores = self.isolation_detector.predict_anomaly_scores(features)
        
        # Normalize all scores to [0, 1]
        hybrid_norm = self._normalize(hybrid_results['hybrid_scores'])
        transformer_norm = self._normalize(transformer_scores)
        isolation_norm = self._normalize(isolation_scores)
        
        # Ensemble voting
        ensemble_scores = (
            self.weights['hybrid'] * hybrid_norm +
            self.weights['transformer'] * transformer_norm +
            self.weights['isolation'] * isolation_norm
        )
        
        return {
            'ensemble_scores': ensemble_scores,
            'hybrid_scores': hybrid_norm,
            'transformer_scores': transformer_norm,
            'isolation_scores': isolation_norm
        }
    
    def predict_anomalies(self, sequences: np.ndarray, features: np.ndarray, 
                         threshold: float = 0.4) -> Dict:
        scores = self.predict_anomaly_scores(sequences, features)
        
        return {
            'ensemble_anomalies': (scores['ensemble_scores'] > threshold).astype(int),
            **scores
        }
    
    def _normalize(self, scores: np.ndarray) -> np.ndarray:
        min_score, max_score = np.min(scores), np.max(scores)
        if max_score == min_score:
            return np.zeros_like(scores)
        return (scores - min_score) / (max_score - min_score)