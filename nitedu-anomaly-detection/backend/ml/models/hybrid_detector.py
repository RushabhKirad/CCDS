import torch
import numpy as np
from typing import Dict, Tuple, Optional
import logging
from .lstm_autoencoder import LSTMAutoencoder
from .isolation_forest import IsolationForestDetector

logger = logging.getLogger(__name__)

class HybridAnomalyDetector:
    def __init__(self, lstm_weight: float = 0.6, isolation_weight: float = 0.4,
                 sequence_length: int = 10, feature_dim: int = 10):
        self.lstm_weight = lstm_weight
        self.isolation_weight = isolation_weight
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        
        # Initialize models
        self.lstm_model = LSTMAutoencoder(
            input_dim=feature_dim,
            sequence_length=sequence_length
        )
        self.isolation_model = IsolationForestDetector()
        
        self.is_fitted = False
        self.lstm_threshold = None
        self.isolation_threshold = None
    
    def fit(self, sequences: np.ndarray, features: np.ndarray) -> 'HybridAnomalyDetector':
        """
        Fit both LSTM and Isolation Forest models
        
        Args:
            sequences: Shape (n_samples, sequence_length, feature_dim)
            features: Shape (n_samples, feature_dim) - aggregated features
        """
        # Train LSTM Autoencoder
        self._train_lstm(sequences)
        
        # Train Isolation Forest
        self.isolation_model.fit(features)
        
        # Calculate thresholds
        self._calculate_thresholds(sequences, features)
        
        self.is_fitted = True
        logger.info("Hybrid detector training completed")
        return self
    
    def _train_lstm(self, sequences: np.ndarray, epochs: int = 50, lr: float = 0.001):
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.lstm_model.to(device)
        
        X_tensor = torch.FloatTensor(sequences).to(device)
        optimizer = torch.optim.Adam(self.lstm_model.parameters(), lr=lr)
        criterion = torch.nn.MSELoss()
        
        self.lstm_model.train()
        for epoch in range(epochs):
            optimizer.zero_grad()
            reconstructed = self.lstm_model(X_tensor)
            loss = criterion(reconstructed, X_tensor)
            loss.backward()
            optimizer.step()
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"LSTM Epoch {epoch+1}/{epochs}, Loss: {loss.item():.6f}")
    
    def _calculate_thresholds(self, sequences: np.ndarray, features: np.ndarray, 
                            percentile: float = 95):
        # LSTM threshold
        X_tensor = torch.FloatTensor(sequences)
        lstm_scores = self.lstm_model.get_reconstruction_error(X_tensor).numpy()
        self.lstm_threshold = np.percentile(lstm_scores, percentile)
        
        # Isolation Forest threshold
        isolation_scores = self.isolation_model.predict_anomaly_scores(features)
        self.isolation_threshold = np.percentile(isolation_scores, percentile)
        
        logger.info(f"Thresholds - LSTM: {self.lstm_threshold:.4f}, "
                   f"Isolation: {self.isolation_threshold:.4f}")
    
    def predict_anomaly_scores(self, sequences: np.ndarray, 
                             features: np.ndarray) -> Dict[str, np.ndarray]:
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        # Get LSTM scores
        X_tensor = torch.FloatTensor(sequences)
        lstm_scores = self.lstm_model.get_reconstruction_error(X_tensor).numpy()
        
        # Get Isolation Forest scores
        isolation_scores = self.isolation_model.predict_anomaly_scores(features)
        
        # Normalize scores to [0, 1]
        lstm_normalized = self._normalize_scores(lstm_scores, self.lstm_threshold)
        isolation_normalized = self._normalize_scores(isolation_scores, self.isolation_threshold)
        
        # Combine scores
        hybrid_scores = (self.lstm_weight * lstm_normalized + 
                        self.isolation_weight * isolation_normalized)
        
        return {
            'lstm_scores': lstm_scores,
            'isolation_scores': isolation_scores,
            'hybrid_scores': hybrid_scores,
            'lstm_normalized': lstm_normalized,
            'isolation_normalized': isolation_normalized
        }
    
    def predict_anomalies(self, sequences: np.ndarray, features: np.ndarray,
                         threshold: float = 0.5) -> Dict[str, np.ndarray]:
        scores = self.predict_anomaly_scores(sequences, features)
        
        return {
            'lstm_anomalies': (scores['lstm_normalized'] > threshold).astype(int),
            'isolation_anomalies': self.isolation_model.predict_anomalies(features),
            'hybrid_anomalies': (scores['hybrid_scores'] > threshold).astype(int),
            **scores
        }
    
    def _normalize_scores(self, scores: np.ndarray, threshold: float) -> np.ndarray:
        # Normalize using threshold as reference point
        normalized = scores / (threshold + 1e-8)
        return np.clip(normalized, 0, 2)  # Cap at 2x threshold
    
    def save_models(self, lstm_path: str, isolation_path: str) -> None:
        if not self.is_fitted:
            raise ValueError("Cannot save unfitted models")
        
        # Save LSTM model
        torch.save({
            'model_state_dict': self.lstm_model.state_dict(),
            'threshold': self.lstm_threshold,
            'sequence_length': self.sequence_length,
            'feature_dim': self.feature_dim
        }, lstm_path)
        
        # Save Isolation Forest
        self.isolation_model.save_model(isolation_path)
        
        logger.info(f"Models saved - LSTM: {lstm_path}, Isolation: {isolation_path}")
    
    def load_models(self, lstm_path: str, isolation_path: str) -> 'HybridAnomalyDetector':
        # Load LSTM model
        checkpoint = torch.load(lstm_path, map_location='cpu')
        self.lstm_model.load_state_dict(checkpoint['model_state_dict'])
        self.lstm_threshold = checkpoint['threshold']
        
        # Load Isolation Forest
        self.isolation_model.load_model(isolation_path)
        
        self.is_fitted = True
        logger.info(f"Models loaded - LSTM: {lstm_path}, Isolation: {isolation_path}")
        return self