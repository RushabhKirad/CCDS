import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from typing import Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class IsolationForestDetector:
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100, 
                 random_state: int = 42, max_samples: str = 'auto'):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.max_samples = max_samples
        
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            max_samples=max_samples
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
    
    def fit(self, X: np.ndarray) -> 'IsolationForestDetector':
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        logger.info(f"Isolation Forest fitted on {X.shape[0]} samples")
        return self
    
    def predict_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_scaled = self.scaler.transform(X)
        # Get anomaly scores (negative values for outliers)
        scores = self.model.decision_function(X_scaled)
        # Convert to positive anomaly scores (higher = more anomalous)
        anomaly_scores = -scores
        return anomaly_scores
    
    def predict_anomalies(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        # Convert to binary (1 = anomaly, 0 = normal)
        return (predictions == -1).astype(int)
    
    def save_model(self, filepath: str) -> None:
        if not self.is_fitted:
            raise ValueError("Cannot save unfitted model")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'contamination': self.contamination,
            'n_estimators': self.n_estimators,
            'is_fitted': self.is_fitted
        }
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str) -> 'IsolationForestDetector':
        model_data = joblib.load(filepath)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.contamination = model_data['contamination']
        self.n_estimators = model_data['n_estimators']
        self.is_fitted = model_data['is_fitted']
        logger.info(f"Model loaded from {filepath}")
        return self