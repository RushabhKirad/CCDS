import pandas as pd
import numpy as np
import torch
import logging
from pathlib import Path
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from ml.models.ensemble_detector import EnsembleAnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealDataTrainer:
    def __init__(self, datasets_dir: str = "datasets"):
        self.datasets_dir = Path(datasets_dir)
        self.scaler = StandardScaler()
        self.label_encoders = {}
        
    def load_nsl_kdd(self):
        """Load NSL-KDD dataset"""
        logger.info("Loading NSL-KDD dataset...")
        
        # Column names for NSL-KDD
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty'
        ]
        
        train_file = self.datasets_dir / "nsl_kdd_train.txt"
        test_file = self.datasets_dir / "nsl_kdd_test.txt"
        
        train_df = pd.read_csv(train_file, names=columns)
        test_df = pd.read_csv(test_file, names=columns)
        
        # Combine datasets
        df = pd.concat([train_df, test_df], ignore_index=True)
        
        # Create binary labels (normal=0, attack=1)
        df['label'] = (df['attack_type'] != 'normal').astype(int)
        
        return df
    
    def load_unsw_nb15(self):
        """Load UNSW-NB15 dataset"""
        logger.info("Loading UNSW-NB15 dataset...")
        
        train_file = self.datasets_dir / "unsw_train.csv"
        test_file = self.datasets_dir / "unsw_test.csv"
        
        train_df = pd.read_csv(train_file)
        test_df = pd.read_csv(test_file)
        
        df = pd.concat([train_df, test_df], ignore_index=True)
        
        # Use existing label column
        df['label'] = df['label']
        
        return df
    
    def preprocess_data(self, df, dataset_name):
        """Preprocess dataset for training"""
        logger.info(f"Preprocessing {dataset_name} data...")
        
        # Remove non-numeric columns except label
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        if 'label' not in numeric_cols:
            numeric_cols.append('label')
        
        # Handle categorical columns
        categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
        if 'label' in categorical_cols:
            categorical_cols.remove('label')
        
        for col in categorical_cols:
            if col not in self.label_encoders:
                self.label_encoders[col] = LabelEncoder()
                df[col] = self.label_encoders[col].fit_transform(df[col].astype(str))
            else:
                df[col] = self.label_encoders[col].transform(df[col].astype(str))
        
        # Select features and labels
        feature_cols = [col for col in df.columns if col not in ['label', 'attack_type', 'difficulty']]
        X = df[feature_cols].fillna(0)
        y = df['label']
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        return X_scaled, y.values
    
    def train_on_real_data(self, sample_size=10000):
        """Train ensemble model on real datasets"""
        logger.info("Training on real network attack datasets...")
        
        all_X = []
        all_y = []
        
        # Load and process each dataset
        try:
            nsl_df = self.load_nsl_kdd()
            X_nsl, y_nsl = self.preprocess_data(nsl_df.sample(min(sample_size, len(nsl_df))), "NSL-KDD")
            all_X.append(X_nsl)
            all_y.append(y_nsl)
            logger.info(f"NSL-KDD: {len(X_nsl)} samples, {np.sum(y_nsl)} attacks")
        except Exception as e:
            logger.warning(f"Failed to load NSL-KDD: {e}")
        
        try:
            unsw_df = self.load_unsw_nb15()
            X_unsw, y_unsw = self.preprocess_data(unsw_df.sample(min(sample_size, len(unsw_df))), "UNSW-NB15")
            all_X.append(X_unsw)
            all_y.append(y_unsw)
            logger.info(f"UNSW-NB15: {len(X_unsw)} samples, {np.sum(y_unsw)} attacks")
        except Exception as e:
            logger.warning(f"Failed to load UNSW-NB15: {e}")
        
        if not all_X:
            raise ValueError("No datasets loaded successfully")
        
        # Combine all datasets
        X_combined = np.vstack(all_X)
        y_combined = np.hstack(all_y)
        
        logger.info(f"Combined dataset: {len(X_combined)} samples, {np.sum(y_combined)} attacks")
        
        # Split into train/test
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y_combined, test_size=0.2, random_state=42, stratify=y_combined
        )
        
        # Use only normal data for training (unsupervised)
        normal_indices = y_train == 0
        X_normal = X_train[normal_indices]
        
        # Create sequences for ensemble training
        sequences = self._create_sequences(X_normal)
        aggregated = np.mean(sequences, axis=1)
        
        # Train ensemble detector
        detector = EnsembleAnomalyDetector(
            sequence_length=10,
            feature_dim=X_normal.shape[1]
        )
        
        detector.fit(sequences, aggregated)
        
        # Test on full test set
        test_sequences = self._create_sequences(X_test)
        test_aggregated = np.mean(test_sequences, axis=1)
        
        results = detector.predict_anomalies(test_sequences, test_aggregated)
        
        # Evaluate
        predictions = results['ensemble_anomalies']
        test_labels = y_test[:len(predictions)]
        
        tp = np.sum((predictions == 1) & (test_labels == 1))
        fp = np.sum((predictions == 1) & (test_labels == 0))
        tn = np.sum((predictions == 0) & (test_labels == 0))
        fn = np.sum((predictions == 0) & (test_labels == 1))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(predictions)
        
        logger.info(f"REAL DATA RESULTS:")
        logger.info(f"  Precision: {precision:.3f}")
        logger.info(f"  Recall: {recall:.3f}")
        logger.info(f"  F1-Score: {f1:.3f}")
        logger.info(f"  Accuracy: {accuracy:.3f}")
        
        return detector
    
    def _create_sequences(self, X, sequence_length=10):
        """Create sequences from feature matrix"""
        if len(X) < sequence_length:
            # Pad with zeros
            padded = np.zeros((sequence_length, X.shape[1]))
            padded[:len(X)] = X
            return padded.reshape(1, sequence_length, X.shape[1])
        
        sequences = []
        for i in range(0, len(X) - sequence_length + 1, sequence_length):
            sequences.append(X[i:i + sequence_length])
        
        return np.array(sequences)

def main():
    trainer = RealDataTrainer()
    detector = trainer.train_on_real_data(sample_size=5000)
    logger.info("Real data training completed!")
    return detector

if __name__ == "__main__":
    main()