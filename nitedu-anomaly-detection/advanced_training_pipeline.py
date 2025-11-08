#!/usr/bin/env python3
"""
Advanced Training Pipeline for State-of-the-Art Cyber Defense
Trains deep learning models on real datasets with advanced techniques
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, precision_recall_curve
from sklearn.preprocessing import LabelEncoder
import logging
import time
import sys

# Import our advanced modules
sys.path.append(str(Path(__file__).parent))
from advanced_feature_engineering import AdvancedFeatureExtractor
from advanced_deep_learning import (
    EnsembleAnomalyDetector, FocalLoss, AdvancedLSTMAutoencoder,
    TransformerAnomalyDetector, ConvolutionalAnomalyDetector, VariationalAutoencoder
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedTrainingPipeline:
    """Advanced training pipeline for cyber defense models"""
    
    def __init__(self, models_dir="data/models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
        self.feature_extractor = AdvancedFeatureExtractor()
        self.models = {}
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        logger.info(f"Using device: {self.device}")
        
    def load_nsl_kdd_dataset(self, sample_size=None):
        """Load and preprocess NSL-KDD dataset"""
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
        
        try:
            # Load training and test data
            train_df = pd.read_csv("datasets/nsl_kdd_train.txt", names=columns, low_memory=False)
            test_df = pd.read_csv("datasets/nsl_kdd_test.txt", names=columns, low_memory=False)
            
            # Combine datasets
            df = pd.concat([train_df, test_df], ignore_index=True)
            
            # Create binary labels (normal=0, attack=1)
            df['label'] = (df['attack_type'] != 'normal').astype(int)
            
            # Sample if requested
            if sample_size and len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)
            
            logger.info(f"NSL-KDD loaded: {len(df)} samples, {df['label'].sum()} attacks")
            return df
            
        except Exception as e:
            logger.error(f"Failed to load NSL-KDD: {e}")
            return None
    
    def load_unsw_nb15_dataset(self, sample_size=None):
        """Load and preprocess UNSW-NB15 dataset"""
        logger.info("Loading UNSW-NB15 dataset...")
        
        try:
            # Load training and test data
            train_df = pd.read_csv("datasets/unsw_train.csv", low_memory=False)
            test_df = pd.read_csv("datasets/unsw_test.csv", low_memory=False)
            
            # Combine datasets
            df = pd.concat([train_df, test_df], ignore_index=True)
            
            # Clean label column
            if 'label' in df.columns:
                df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
            elif 'Label' in df.columns:
                df['label'] = pd.to_numeric(df['Label'], errors='coerce').fillna(0).astype(int)
            else:
                df['label'] = 0
            
            # Sample if requested
            if sample_size and len(df) > sample_size:
                df = df.sample(n=sample_size, random_state=42)
            
            logger.info(f"UNSW-NB15 loaded: {len(df)} samples, {df['label'].sum()} attacks")
            return df
            
        except Exception as e:
            logger.error(f"Failed to load UNSW-NB15: {e}")
            return None
    
    def create_synthetic_advanced_data(self, n_samples=10000):
        """Create advanced synthetic data with realistic attack patterns"""
        logger.info(f"Creating advanced synthetic data ({n_samples} samples)...")
        
        data = []
        
        # Normal traffic (70%)
        for i in range(int(n_samples * 0.7)):
            sample = {
                'path': np.random.choice(['/', '/home', '/about', '/contact', '/products']),
                'user_agent': np.random.choice([
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                ]),
                'method': np.random.choice(['GET', 'POST'], p=[0.8, 0.2]),
                'country': np.random.choice(['US', 'CA', 'GB', 'DE', 'FR'], p=[0.4, 0.2, 0.15, 0.15, 0.1]),
                'ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 60,
                'duration': np.random.normal(0.2, 0.1),
                'src_bytes': int(np.random.normal(1500, 500)),
                'dst_bytes': int(np.random.normal(500, 200)),
                'src_packets': int(np.random.normal(10, 3)),
                'dst_packets': int(np.random.normal(8, 2)),
                'protocol': 'HTTPS',
                'src_port': np.random.randint(1024, 65535),
                'dst_port': np.random.choice([80, 443, 8080]),
                'content_length': int(np.random.normal(2000, 800))
            }
            sample['label'] = 0
            data.append(sample)
        
        # SQL Injection attacks (10%)
        for i in range(int(n_samples * 0.1)):
            sql_payloads = [
                "/?id=1' OR '1'='1",
                "/login?user=admin' UNION SELECT * FROM users--",
                "/search?q='; DROP TABLE users; --",
                "/?page=1' AND 1=1--",
                "/product?id=1' OR 1=1 UNION SELECT password FROM admin--"
            ]
            
            sample = {
                'path': np.random.choice(sql_payloads),
                'user_agent': np.random.choice(['sqlmap/1.6.12', 'python-requests/2.28.1', 'curl/7.68.0']),
                'method': np.random.choice(['GET', 'POST']),
                'country': np.random.choice(['CN', 'RU', 'KP', 'IR']),
                'ip': f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 30,
                'duration': np.random.normal(0.05, 0.02),
                'src_bytes': int(np.random.normal(800, 200)),
                'dst_bytes': int(np.random.normal(200, 100)),
                'src_packets': int(np.random.normal(5, 2)),
                'dst_packets': int(np.random.normal(3, 1)),
                'protocol': 'HTTP',
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 80,
                'content_length': int(np.random.normal(600, 200))
            }
            sample['label'] = 1
            data.append(sample)
        
        # XSS attacks (8%)
        for i in range(int(n_samples * 0.08)):
            xss_payloads = [
                "/search?q=<script>alert('XSS')</script>",
                "/?name=<img src=x onerror=alert(1)>",
                "/comment?text=<iframe src=javascript:alert('XSS')></iframe>",
                "/?input=javascript:alert(document.cookie)",
                "/profile?bio=<svg onload=alert('XSS')>"
            ]
            
            sample = {
                'path': np.random.choice(xss_payloads),
                'user_agent': np.random.choice([
                    'Mozilla/5.0 (Windows NT 6.1; WOW64)',
                    'curl/7.68.0',
                    'python-requests/2.28.1'
                ]),
                'method': np.random.choice(['GET', 'POST']),
                'country': np.random.choice(['CN', 'RU', 'BR', 'IN']),
                'ip': f"172.16.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 45,
                'duration': np.random.normal(0.08, 0.03),
                'src_bytes': int(np.random.normal(700, 150)),
                'dst_bytes': int(np.random.normal(300, 100)),
                'src_packets': int(np.random.normal(6, 2)),
                'dst_packets': int(np.random.normal(4, 1)),
                'protocol': 'HTTP',
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 80,
                'content_length': int(np.random.normal(500, 150))
            }
            sample['label'] = 1
            data.append(sample)
        
        # Bot/Scraper attacks (7%)
        for i in range(int(n_samples * 0.07)):
            bot_agents = [
                'Googlebot/2.1',
                'bingbot/2.0',
                'python-requests/2.28.1',
                'curl/7.68.0',
                'wget/1.20.3',
                'scrapy/2.6.1',
                'Baiduspider/2.0'
            ]
            
            sample = {
                'path': np.random.choice(['/robots.txt', '/sitemap.xml', '/admin', '/api/data']),
                'user_agent': np.random.choice(bot_agents),
                'method': 'GET',
                'country': np.random.choice(['CN', 'RU', 'US', 'DE']),
                'ip': f"203.0.113.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 10,
                'duration': np.random.normal(0.02, 0.01),
                'src_bytes': int(np.random.normal(300, 100)),
                'dst_bytes': int(np.random.normal(5000, 1000)),
                'src_packets': int(np.random.normal(15, 5)),
                'dst_packets': int(np.random.normal(20, 5)),
                'protocol': 'HTTP',
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 80,
                'content_length': int(np.random.normal(200, 50))
            }
            sample['label'] = 1
            data.append(sample)
        
        # DDoS attacks (5%)
        for i in range(int(n_samples * 0.05)):
            sample = {
                'path': '/',
                'user_agent': np.random.choice(['curl/7.68.0', 'wget/1.20.3', '']),
                'method': 'GET',
                'country': np.random.choice(['CN', 'RU', 'KP']),
                'ip': f"198.51.100.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 5,
                'duration': np.random.normal(0.001, 0.0005),
                'src_bytes': int(np.random.normal(100, 50)),
                'dst_bytes': int(np.random.normal(50, 20)),
                'src_packets': int(np.random.normal(50, 20)),
                'dst_packets': int(np.random.normal(2, 1)),
                'protocol': 'TCP',
                'src_port': np.random.randint(1024, 65535),
                'dst_port': 80,
                'content_length': int(np.random.normal(100, 30))
            }
            sample['label'] = 1
            data.append(sample)
        
        logger.info(f"Created {len(data)} synthetic samples")
        return data
    
    def create_enhanced_attack_data(self, n_samples=2500):
        """Create training data for missed attack types"""
        logger.info(f"Creating enhanced attack data ({n_samples} samples)...")
        
        data = []
        
        # Business Logic attacks (20%)
        for i in range(int(n_samples * 0.2)):
            business_payloads = [
                "/checkout?price=-100",
                "/admin?role=admin", 
                "/discount?amount=100",
                "/user?isadmin=1",
                "/price?value=-999"
            ]
            
            sample = {
                'path': np.random.choice(business_payloads),
                'user_agent': 'Mozilla/5.0',
                'method': 'POST',
                'country': 'US',
                'ip': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 60,
                'duration': 0.1,
                'src_bytes': 500,
                'dst_bytes': 200,
                'src_packets': 3,
                'dst_packets': 2,
                'protocol': 'HTTPS',
                'src_port': 443,
                'dst_port': 80,
                'content_length': 300,
                'label': 1
            }
            data.append(sample)
        
        # LDAP Injection (15%)
        for i in range(int(n_samples * 0.15)):
            ldap_payloads = [
                "/search?user=*)(uid=*))(|(uid=*",
                "/login?name=admin)(cn=*",
                "/auth?filter=(|(cn=*)(uid=*))",
                "/user?query=(&(objectClass=*))"
            ]
            
            sample = {
                'path': np.random.choice(ldap_payloads),
                'user_agent': 'Mozilla/5.0',
                'method': 'GET',
                'country': 'CN',
                'ip': f"10.0.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 45,
                'duration': 0.08,
                'src_bytes': 400,
                'dst_bytes': 150,
                'src_packets': 4,
                'dst_packets': 2,
                'protocol': 'HTTP',
                'src_port': 1024,
                'dst_port': 389,
                'content_length': 250,
                'label': 1
            }
            data.append(sample)
        
        # Template Injection (15%)
        for i in range(int(n_samples * 0.15)):
            template_payloads = [
                "/profile?name={{7*7}}",
                "/search?q=${7*7}",
                "/render?template=<%=7*7%>",
                "/view?data={%7*7%}"
            ]
            
            sample = {
                'path': np.random.choice(template_payloads),
                'user_agent': 'Mozilla/5.0',
                'method': 'GET',
                'country': 'RU',
                'ip': f"172.16.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 30,
                'duration': 0.12,
                'src_bytes': 350,
                'dst_bytes': 180,
                'src_packets': 5,
                'dst_packets': 3,
                'protocol': 'HTTP',
                'src_port': 2048,
                'dst_port': 80,
                'content_length': 200,
                'label': 1
            }
            data.append(sample)
        
        # Session Hijacking (15%)
        for i in range(int(n_samples * 0.15)):
            session_payloads = [
                "/dashboard?PHPSESSID=hijacked123",
                "/account?sessionid=stolen456",
                "/admin?JSESSIONID=malicious789",
                "/profile?session_token=fake_token"
            ]
            
            sample = {
                'path': np.random.choice(session_payloads),
                'user_agent': 'Mozilla/5.0',
                'method': 'GET',
                'country': 'BR',
                'ip': f"203.0.113.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 20,
                'duration': 0.15,
                'src_bytes': 600,
                'dst_bytes': 300,
                'src_packets': 8,
                'dst_packets': 5,
                'protocol': 'HTTPS',
                'src_port': 443,
                'dst_port': 443,
                'content_length': 400,
                'label': 1
            }
            data.append(sample)
        
        # Brute Force (10%)
        for i in range(int(n_samples * 0.1)):
            brute_agents = ['hydra', 'medusa', 'john/1.9', 'hashcat', 'brutespray']
            
            sample = {
                'path': '/login',
                'user_agent': np.random.choice(brute_agents),
                'method': 'POST',
                'country': 'KP',
                'ip': f"198.51.100.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 5,
                'duration': 0.02,
                'src_bytes': 200,
                'dst_bytes': 100,
                'src_packets': 2,
                'dst_packets': 1,
                'protocol': 'HTTP',
                'src_port': 4444,
                'dst_port': 80,
                'content_length': 150,
                'label': 1
            }
            data.append(sample)
        
        # Cryptojacking (10%)
        for i in range(int(n_samples * 0.1)):
            crypto_payloads = [
                "/js/coinhive.min.js",
                "/miner?algo=cryptonight",
                "/crypto/monero.js",
                "/mining/xmrig.wasm"
            ]
            
            sample = {
                'path': np.random.choice(crypto_payloads),
                'user_agent': 'Mozilla/5.0',
                'method': 'GET',
                'country': 'IR',
                'ip': f"192.0.2.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 120,
                'duration': 0.5,
                'src_bytes': 1000,
                'dst_bytes': 5000,
                'src_packets': 15,
                'dst_packets': 20,
                'protocol': 'HTTPS',
                'src_port': 443,
                'dst_port': 443,
                'content_length': 800,
                'label': 1
            }
            data.append(sample)
        
        # PII/Credit Card (15%)
        for i in range(int(n_samples * 0.15)):
            pii_payloads = [
                "/form?ssn=123-45-6789",
                "/payment?cc=4111111111111111",
                "/profile?passport=A12345678",
                "/checkout?card=5555555555554444"
            ]
            
            sample = {
                'path': np.random.choice(pii_payloads),
                'user_agent': 'Mozilla/5.0',
                'method': 'POST',
                'country': 'PK',
                'ip': f"203.0.113.{np.random.randint(1, 255)}",
                'timestamp': 1640995200 + i * 90,
                'duration': 0.3,
                'src_bytes': 800,
                'dst_bytes': 400,
                'src_packets': 10,
                'dst_packets': 6,
                'protocol': 'HTTPS',
                'src_port': 443,
                'dst_port': 443,
                'content_length': 600,
                'label': 1
            }
            data.append(sample)
        
        logger.info(f"Created {len(data)} enhanced attack samples")
        return data
    
    def prepare_training_data(self, sample_size=15000):
        """Prepare comprehensive training data"""
        logger.info("Preparing training data...")
        
        all_data = []
        
        # Try to load real datasets
        nsl_df = self.load_nsl_kdd_dataset(sample_size // 3)
        if nsl_df is not None:
            # Convert NSL-KDD to our format
            for _, row in nsl_df.iterrows():
                sample = {
                    'duration': row.get('duration', 0),
                    'src_bytes': row.get('src_bytes', 0),
                    'dst_bytes': row.get('dst_bytes', 0),
                    'protocol': row.get('protocol_type', 'tcp'),
                    'method': 'GET',
                    'path': '/',
                    'user_agent': 'Mozilla/5.0',
                    'country': 'US',
                    'ip': '192.168.1.1',
                    'timestamp': 1640995200,
                    'src_packets': row.get('count', 1),
                    'dst_packets': row.get('srv_count', 1),
                    'src_port': 1024,
                    'dst_port': 80,
                    'content_length': int(row.get('src_bytes', 0)),
                    'label': row['label']
                }
                all_data.append(sample)
        
        unsw_df = self.load_unsw_nb15_dataset(sample_size // 3)
        if unsw_df is not None:
            # Convert UNSW-NB15 to our format
            for _, row in nsl_df.iterrows():
                sample = {
                    'duration': row.get('dur', 0),
                    'src_bytes': row.get('sbytes', 0),
                    'dst_bytes': row.get('dbytes', 0),
                    'protocol': row.get('proto', 'tcp'),
                    'method': 'GET',
                    'path': '/',
                    'user_agent': 'Mozilla/5.0',
                    'country': 'US',
                    'ip': '192.168.1.1',
                    'timestamp': 1640995200,
                    'src_packets': row.get('spkts', 1),
                    'dst_packets': row.get('dpkts', 1),
                    'src_port': row.get('sport', 1024),
                    'dst_port': row.get('dport', 80),
                    'content_length': int(row.get('sbytes', 0)),
                    'label': row['label']
                }
                all_data.append(sample)
        
        # Add synthetic data with enhanced attack types
        synthetic_data = self.create_synthetic_advanced_data(sample_size // 2)
        enhanced_data = self.create_enhanced_attack_data(sample_size // 4)
        all_data.extend(synthetic_data)
        all_data.extend(enhanced_data)
        
        logger.info(f"Total training data: {len(all_data)} samples")
        
        # Extract advanced features
        features = self.feature_extractor.fit_transform(all_data)
        labels = np.array([sample['label'] for sample in all_data])
        
        return features, labels
    
    def train_ensemble_model(self, X_train, y_train, X_val, y_val, epochs=100, batch_size=64):
        """Train the ensemble deep learning model"""
        logger.info("Training ensemble deep learning model...")
        
        # Convert to PyTorch tensors
        X_train_tensor = torch.FloatTensor(X_train).to(self.device)
        y_train_tensor = torch.FloatTensor(y_train).to(self.device)
        X_val_tensor = torch.FloatTensor(X_val).to(self.device)
        y_val_tensor = torch.FloatTensor(y_val).to(self.device)
        
        # Create data loaders
        train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        
        # Initialize ensemble model
        model = EnsembleAnomalyDetector(input_size=100, sequence_length=10).to(self.device)
        
        # Loss function and optimizer
        criterion = FocalLoss(alpha=1, gamma=2)
        optimizer = optim.AdamW(model.parameters(), lr=0.001, weight_decay=0.01)
        scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=10, factor=0.5)
        
        # Training loop
        best_val_auc = 0
        patience_counter = 0
        
        for epoch in range(epochs):
            model.train()
            train_loss = 0
            
            for batch_X, batch_y in train_loader:
                optimizer.zero_grad()
                
                outputs = model(batch_X)
                loss = criterion(outputs, batch_y)
                
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                
                train_loss += loss.item()
            
            # Validation
            model.eval()
            with torch.no_grad():
                val_outputs = model(X_val_tensor)
                val_loss = criterion(val_outputs, y_val_tensor)
                
                # Calculate AUC
                val_probs = val_outputs.cpu().numpy()
                val_auc = roc_auc_score(y_val, val_probs)
            
            scheduler.step(val_loss)
            
            # Early stopping
            if val_auc > best_val_auc:
                best_val_auc = val_auc
                patience_counter = 0
                # Save best model
                torch.save(model.state_dict(), self.models_dir / "ensemble_model_best.pth")
            else:
                patience_counter += 1
            
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch+1}/{epochs}")
                logger.info(f"  Train Loss: {train_loss/len(train_loader):.4f}")
                logger.info(f"  Val Loss: {val_loss:.4f}")
                logger.info(f"  Val AUC: {val_auc:.4f}")
                logger.info(f"  Best AUC: {best_val_auc:.4f}")
            
            if patience_counter >= 20:
                logger.info("Early stopping triggered")
                break
        
        # Load best model
        model.load_state_dict(torch.load(self.models_dir / "ensemble_model_best.pth"))
        
        return model, best_val_auc
    
    def evaluate_model(self, model, X_test, y_test):
        """Evaluate the trained model"""
        logger.info("Evaluating model...")
        
        model.eval()
        X_test_tensor = torch.FloatTensor(X_test).to(self.device)
        
        with torch.no_grad():
            # Get ensemble predictions
            ensemble_probs = model(X_test_tensor).cpu().numpy()
            ensemble_preds = (ensemble_probs > 0.5).astype(int)
            
            # Get individual model predictions
            individual_preds = model.get_individual_predictions(X_test_tensor)
        
        # Calculate metrics
        ensemble_auc = roc_auc_score(y_test, ensemble_probs)
        
        logger.info("Ensemble Model Results:")
        logger.info(f"  AUC: {ensemble_auc:.4f}")
        logger.info(classification_report(y_test, ensemble_preds))
        
        # Individual model performance
        logger.info("Individual Model AUCs:")
        for model_name, probs in individual_preds.items():
            auc = roc_auc_score(y_test, probs.cpu().numpy())
            logger.info(f"  {model_name}: {auc:.4f}")
        
        return {
            'ensemble_auc': ensemble_auc,
            'ensemble_probs': ensemble_probs,
            'individual_aucs': {name: roc_auc_score(y_test, probs.cpu().numpy()) 
                              for name, probs in individual_preds.items()}
        }
    
    def save_models(self, model, results):
        """Save trained models and metadata"""
        logger.info("Saving models...")
        
        # Save ensemble model
        torch.save(model.state_dict(), self.models_dir / "advanced_ensemble_model.pth")
        
        # Save feature extractor
        joblib.dump(self.feature_extractor, self.models_dir / "advanced_feature_extractor.joblib")
        
        # Save metadata
        metadata = {
            'model_type': 'advanced_ensemble',
            'input_size': 100,
            'sequence_length': 10,
            'ensemble_auc': results['ensemble_auc'],
            'individual_aucs': results['individual_aucs'],
            'feature_extractor_fitted': True
        }
        joblib.dump(metadata, self.models_dir / "advanced_model_metadata.joblib")
        
        logger.info(f"Models saved to {self.models_dir}")
    
    def run_advanced_training(self, sample_size=15000):
        """Run complete advanced training pipeline"""
        logger.info("🚀 Starting Advanced ML Training Pipeline")
        logger.info("=" * 60)
        
        start_time = time.time()
        
        # Prepare data
        X, y = self.prepare_training_data(sample_size)
        
        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.4, random_state=42, stratify=y
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
        )
        
        logger.info(f"Data split:")
        logger.info(f"  Train: {X_train.shape[0]} samples")
        logger.info(f"  Validation: {X_val.shape[0]} samples")
        logger.info(f"  Test: {X_test.shape[0]} samples")
        
        # Train model
        model, best_auc = self.train_ensemble_model(X_train, y_train, X_val, y_val)
        
        # Evaluate model
        results = self.evaluate_model(model, X_test, y_test)
        
        # Save models
        self.save_models(model, results)
        
        training_time = time.time() - start_time
        
        logger.info("🎯 Advanced Training Completed!")
        logger.info("=" * 60)
        logger.info(f"Training Time: {training_time:.2f} seconds")
        logger.info(f"Final Test AUC: {results['ensemble_auc']:.4f}")
        logger.info(f"Individual Model AUCs:")
        for name, auc in results['individual_aucs'].items():
            logger.info(f"  {name}: {auc:.4f}")
        
        return results

def main():
    """Main training function"""
    pipeline = AdvancedTrainingPipeline()
    results = pipeline.run_advanced_training(sample_size=10000)
    
    print("\n🛡️ ADVANCED COGNITIVE CYBER DEFENSE TRAINING COMPLETE")
    print("=" * 70)
    print(f"✅ Ensemble Model AUC: {results['ensemble_auc']:.4f}")
    print(f"✅ Individual Models:")
    for name, auc in results['individual_aucs'].items():
        print(f"   {name.upper()}: {auc:.4f}")
    print(f"📁 Models saved to: data/models/")
    print("🚀 Ready for production deployment!")

if __name__ == "__main__":
    main()