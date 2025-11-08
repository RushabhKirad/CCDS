import numpy as np
import torch
import logging
from pathlib import Path
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from ml.models.ensemble_detector import EnsembleAnomalyDetector
from ml.models.online_learner import OnlineLearningDetector
from ml.preprocessing.feature_extractor import NetworkFeatureExtractor
from ml.training.synthetic_data_generator import SyntheticNetworkDataGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedModelTrainer:
    def __init__(self, data_dir: str = "data", models_dir: str = "data/models"):
        self.data_dir = Path(data_dir)
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.data_generator = SyntheticNetworkDataGenerator()
        self.feature_extractor = NetworkFeatureExtractor()
        
    def train_enhanced_model(self, normal_samples: int = 3000, 
                           anomaly_samples: int = 150) -> EnsembleAnomalyDetector:
        """Train enhanced ensemble model with multiple detectors"""
        
        logger.info("Generating enhanced training data...")
        events, labels = self.data_generator.generate_mixed_dataset(
            normal_count=normal_samples, 
            anomaly_count=anomaly_samples
        )
        
        # Extract enhanced features
        features = self.feature_extractor.extract_features(events)
        sequences, aggregated_features = self.feature_extractor.create_sequences(
            features, sequence_length=10
        )
        
        # Filter normal data for training
        normal_indices = np.where(labels[:len(sequences)] == False)[0]
        normal_sequences = sequences[normal_indices]
        normal_aggregated = aggregated_features[normal_indices]
        
        logger.info(f"Training ensemble on {len(normal_sequences)} normal sequences")
        
        # Train ensemble detector
        ensemble = EnsembleAnomalyDetector(
            sequence_length=10,
            feature_dim=features.shape[1]
        )
        
        ensemble.fit(normal_sequences, normal_aggregated)
        
        # Evaluate performance
        results = ensemble.predict_anomalies(sequences, aggregated_features)
        true_labels = labels[:len(sequences)]
        
        self._evaluate_ensemble(results, true_labels)
        
        logger.info("Enhanced model training completed!")
        return ensemble
    
    def _evaluate_ensemble(self, results: dict, true_labels: np.ndarray):
        """Evaluate ensemble performance"""
        predictions = results['ensemble_anomalies']
        
        tp = np.sum((predictions == 1) & (true_labels == 1))
        fp = np.sum((predictions == 1) & (true_labels == 0))
        tn = np.sum((predictions == 0) & (true_labels == 0))
        fn = np.sum((predictions == 0) & (true_labels == 1))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(predictions)
        
        logger.info(f"ENSEMBLE - Precision: {precision:.3f}, Recall: {recall:.3f}, "
                   f"F1: {f1:.3f}, Accuracy: {accuracy:.3f}")

def main():
    trainer = EnhancedModelTrainer()
    ensemble = trainer.train_enhanced_model()
    return ensemble

if __name__ == "__main__":
    main()