#!/usr/bin/env python3
"""
Advanced ML Inference Engine for Production
Real-time anomaly detection with state-of-the-art models
"""

import torch
import joblib
import numpy as np
import time
import logging
from pathlib import Path
from typing import Dict, List, Any
import sys

# Import advanced modules
sys.path.append(str(Path(__file__).parent))
from advanced_feature_engineering import AdvancedFeatureExtractor
from advanced_deep_learning import EnsembleAnomalyDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdvancedInferenceEngine:
    """Production-grade ML inference engine"""
    
    def __init__(self, models_dir: str = "data/models"):
        self.models_dir = Path(models_dir)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Model components
        self.ensemble_model = None
        self.feature_extractor = None
        self.metadata = None
        self.is_loaded = False
        
        # Performance tracking
        self.inference_count = 0
        self.total_inference_time = 0
        
        logger.info(f"Advanced Inference Engine initialized on {self.device}")
    
    def load_models(self):
        """Load all advanced models"""
        logger.info("Loading advanced ML models...")
        
        try:
            # Load metadata
            metadata_path = self.models_dir / "advanced_model_metadata.joblib"
            if metadata_path.exists():
                self.metadata = joblib.load(metadata_path)
                logger.info(f"Loaded metadata: {self.metadata}")
            else:
                logger.warning("Advanced metadata not found, using defaults")
                self.metadata = {
                    'model_type': 'advanced_ensemble',
                    'input_size': 100,
                    'sequence_length': 10
                }
            
            # Load feature extractor
            extractor_path = self.models_dir / "advanced_feature_extractor.joblib"
            if extractor_path.exists():
                self.feature_extractor = joblib.load(extractor_path)
                logger.info("✅ Advanced feature extractor loaded")
            else:
                logger.warning("❌ Advanced feature extractor not found")
                return False
            
            # Load ensemble model
            model_path = self.models_dir / "advanced_ensemble_model.pth"
            if model_path.exists():
                self.ensemble_model = EnsembleAnomalyDetector(
                    input_size=self.metadata['input_size'],
                    sequence_length=self.metadata['sequence_length']
                ).to(self.device)
                
                state_dict = torch.load(model_path, map_location=self.device)
                self.ensemble_model.load_state_dict(state_dict)
                self.ensemble_model.eval()
                
                logger.info("✅ Advanced ensemble model loaded")
            else:
                logger.warning("❌ Advanced ensemble model not found")
                return False
            
            self.is_loaded = True
            logger.info("🚀 All advanced models loaded successfully!")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load advanced models: {e}")
            self.is_loaded = False
            return False
    
    def predict_anomaly(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced anomaly prediction with detailed analysis"""
        
        if not self.is_loaded:
            return {
                'error': 'Advanced models not loaded',
                'is_anomaly': False,
                'confidence': 0.0,
                'model_type': 'fallback'
            }
        
        start_time = time.time()
        
        try:
            # Extract advanced features
            features = self.feature_extractor.transform(request_data)
            
            # Convert to tensor
            features_tensor = torch.FloatTensor(features).to(self.device)
            
            # Get ensemble prediction
            with torch.no_grad():
                ensemble_prob = self.ensemble_model(features_tensor).cpu().numpy()[0]
                
                # Get individual model predictions for detailed analysis
                individual_preds = self.ensemble_model.get_individual_predictions(features_tensor)
                individual_scores = {
                    name: float(pred.cpu().numpy()[0]) 
                    for name, pred in individual_preds.items()
                }
            
            # Determine anomaly with adaptive threshold
            base_threshold = 0.5
            confidence_threshold = self._calculate_adaptive_threshold(individual_scores)
            
            # Use optimized threshold
            is_anomaly = ensemble_prob > 0.50
            confidence = float(ensemble_prob)
            
            # Classify attack type with advanced analysis
            attack_type, attack_confidence = self._classify_advanced_attack_type(
                request_data, features[0], individual_scores
            )
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(
                confidence, individual_scores, request_data
            )
            
            # Performance tracking
            inference_time = time.time() - start_time
            self.inference_count += 1
            self.total_inference_time += inference_time
            
            return {
                'is_anomaly': is_anomaly,
                'confidence': confidence,
                'risk_score': risk_score,
                'attack_type': attack_type,
                'attack_confidence': attack_confidence,
                'model_scores': {
                    'ensemble': confidence,
                    **individual_scores
                },
                'threshold_used': confidence_threshold,
                'inference_time_ms': inference_time * 1000,
                'model_type': 'advanced_ensemble',
                'feature_vector_size': len(features[0]),
                'detailed_analysis': self._get_detailed_analysis(
                    request_data, features[0], individual_scores
                )
            }
            
        except Exception as e:
            logger.error(f"Advanced prediction error: {e}")
            return {
                'error': str(e),
                'is_anomaly': False,
                'confidence': 0.0,
                'model_type': 'error'
            }
    
    def _calculate_adaptive_threshold(self, individual_scores: Dict[str, float]) -> float:
        """Calculate adaptive threshold based on model agreement"""
        
        scores = list(individual_scores.values())
        
        # If models agree (low variance), use lower threshold
        score_variance = np.var(scores)
        score_mean = np.mean(scores)
        
        if score_variance < 0.1:  # High agreement
            if score_mean > 0.7:
                return 0.4  # Lower threshold for high-confidence attacks
            else:
                return 0.6  # Higher threshold for low-confidence
        else:  # Low agreement
            return 0.5  # Standard threshold
    
    def _classify_advanced_attack_type(self, request_data: Dict[str, Any], 
                                     features: np.ndarray, 
                                     individual_scores: Dict[str, float]) -> tuple:
        """Enhanced attack type classification with pattern matching"""
        from urllib.parse import unquote
        
        path = unquote(str(request_data.get('path', ''))).lower()
        user_agent = str(request_data.get('user_agent', '')).lower()
        method = request_data.get('method', 'GET')
        
        # Priority-based pattern matching (most specific first)
        
        # 1. Advanced Scanner Detection
        if any(pattern in user_agent for pattern in ['sqlmap', 'nikto', 'nmap', 'masscan', 'zap', 'burp', 'w3af', 'scanner']):
            return ('Advanced Scanner', 0.95)
        
        # 2. SQL Injection
        if any(pattern in path for pattern in ['union', 'select', 'drop', "' or '", "'=''", '--', 'insert', 'delete', 'update', 'information_schema']):
            return ('SQL Injection', 0.92)
        
        # 3. XSS Attack
        if any(pattern in path for pattern in ['<script', 'javascript:', 'alert(', 'onerror=', '<iframe', 'onload=', 'onclick=', 'document.cookie']):
            return ('XSS Attack', 0.88)
        
        # 4. Command Injection
        if any(pattern in path for pattern in ['|', '&&', ';', '$(', '`', 'cat ', 'ls ', 'wget ', 'curl ', 'nc ', 'whoami']):
            return ('Command Injection', 0.90)
        
        # 5. Directory Traversal
        if any(pattern in path for pattern in ['../', '..\\', '%2e%2e', '%252e', '....///', '..%2f', '..%5c']):
            return ('Directory Traversal', 0.85)
        
        # 6. XML Injection
        if any(pattern in path for pattern in ['<!entity', '<!doctype', 'system "', 'public "', '&xxe;', 'file:///']):
            return ('XML Injection', 0.83)
        
        # 7. LDAP Injection
        if any(pattern in path for pattern in ['*)(', '*)(&', '*))%00', '*()|', '*)(cn=*']):
            return ('LDAP Injection', 0.87)
        
        # 8. NoSQL Injection
        if any(pattern in path for pattern in ['$ne', '$gt', '$where', '$regex', '[$gt]', '{"$ne":', '[$where]']):
            return ('NoSQL Injection', 0.86)
        
        # 9. SSRF Attack
        if any(pattern in path for pattern in ['localhost', '127.0.0.1', '0.0.0.0', 'file://', 'gopher://', 'dict://', 'ftp://localhost']):
            return ('SSRF Attack', 0.84)
        
        # 10. File Upload Attack
        if any(pattern in path for pattern in ['.php', '.jsp', '.asp', '.exe', '.sh', '.py', '.pl', '.rb']):
            return ('File Upload Attack', 0.82)
        
        # 11. Brute Force
        if method == 'POST' and any(pattern in path for pattern in ['login', 'auth', 'signin', 'admin']):
            return ('Brute Force', 0.70)
        
        # 12. Generic Bot (lower priority)
        if any(pattern in user_agent for pattern in ['bot', 'crawler', 'spider', 'curl', 'python', 'wget']):
            return ('Bot Traffic', 0.75)
        
        # Fallback to ML-based classification
        lstm_confidence = individual_scores.get('lstm', 0)
        transformer_confidence = individual_scores.get('transformer', 0)
        cnn_confidence = individual_scores.get('cnn', 0)
        vae_confidence = individual_scores.get('vae', 0)
        
        # Advanced Persistent Threat (multiple model agreement)
        if (lstm_confidence > 0.6 and transformer_confidence > 0.6 and cnn_confidence > 0.6):
            return ('Advanced Persistent Threat', 0.95)
        
        # Zero-day Attack (VAE high anomaly + low other scores)
        if vae_confidence > 0.8 and max(lstm_confidence, transformer_confidence, cnn_confidence) < 0.5:
            return ('Zero-day Attack', 0.7)
        
        # DDoS (VAE detection)
        if vae_confidence > 0.8:
            return ('DDoS Attack', 0.9)
        
        # Generic Anomaly
        if max(individual_scores.values()) > 0.5:
            return ('Generic Anomaly', 0.6)
        
        return ('Normal Traffic', 0.1)
    
    def _calculate_risk_score(self, confidence: float, 
                            individual_scores: Dict[str, float], 
                            request_data: Dict[str, Any]) -> float:
        """Calculate comprehensive risk score"""
        
        # Base risk from model confidence
        base_risk = confidence
        
        # Geographic risk multiplier
        country = request_data.get('country', 'US')
        high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'PK']
        geo_multiplier = 1.3 if country in high_risk_countries else 1.0
        
        # Time-based risk (night hours are riskier)
        timestamp = request_data.get('timestamp', 0)
        if timestamp > 0:
            hour = (timestamp % 86400) // 3600
            time_multiplier = 1.2 if hour < 6 or hour > 22 else 1.0
        else:
            time_multiplier = 1.0
        
        # Model agreement factor
        scores = list(individual_scores.values())
        agreement = 1 - np.var(scores)  # High agreement = low variance
        agreement_multiplier = 1.0 + (agreement * 0.3)
        
        # Calculate final risk score
        risk_score = base_risk * geo_multiplier * time_multiplier * agreement_multiplier
        
        return min(risk_score, 1.0)  # Cap at 1.0
    
    def _get_detailed_analysis(self, request_data: Dict[str, Any], 
                             features: np.ndarray, 
                             individual_scores: Dict[str, float]) -> Dict[str, Any]:
        """Get detailed analysis of the request"""
        
        return {
            'payload_analysis': {
                'sql_injection_score': float(features[0]) if len(features) > 0 else 0,
                'xss_score': float(features[1]) if len(features) > 1 else 0,
                'command_injection_score': float(features[2]) if len(features) > 2 else 0,
                'path_entropy': float(features[5]) if len(features) > 5 else 0,
                'suspicious_chars': float(features[6]) if len(features) > 6 else 0
            },
            'behavioral_analysis': {
                'user_agent_entropy': float(features[13]) if len(features) > 13 else 0,
                'bot_indicators': float(features[14]) if len(features) > 14 else 0,
                'geographic_risk': 1 if request_data.get('country') in ['CN', 'RU', 'KP'] else 0,
                'timing_anomaly': self._check_timing_anomaly(request_data)
            },
            'network_analysis': {
                'packet_analysis': float(features[10]) if len(features) > 10 else 0,
                'byte_analysis': float(features[11]) if len(features) > 11 else 0,
                'flow_characteristics': float(features[12]) if len(features) > 12 else 0
            },
            'model_consensus': {
                'high_agreement': np.var(list(individual_scores.values())) < 0.1,
                'dominant_model': max(individual_scores.items(), key=lambda x: x[1])[0],
                'confidence_spread': max(individual_scores.values()) - min(individual_scores.values())
            }
        }
    
    def _check_timing_anomaly(self, request_data: Dict[str, Any]) -> float:
        """Check for timing-based anomalies"""
        timestamp = request_data.get('timestamp', 0)
        if timestamp == 0:
            return 0.0
        
        # Check if request is during suspicious hours
        hour = (timestamp % 86400) // 3600
        if hour < 6 or hour > 22:  # Night hours
            return 0.8
        elif 9 <= hour <= 17:  # Business hours
            return 0.2
        else:
            return 0.4
    
    def batch_predict(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch prediction for multiple requests"""
        
        if not self.is_loaded:
            return [{'error': 'Models not loaded'} for _ in requests]
        
        results = []
        
        try:
            # Extract features for all requests
            features_batch = []
            for request in requests:
                features = self.feature_extractor.transform(request)
                features_batch.append(features[0])
            
            features_batch = np.array(features_batch)
            features_tensor = torch.FloatTensor(features_batch).to(self.device)
            
            # Batch prediction
            with torch.no_grad():
                ensemble_probs = self.ensemble_model(features_tensor).cpu().numpy()
                individual_preds_batch = self.ensemble_model.get_individual_predictions(features_tensor)
            
            # Process results
            for i, (request, ensemble_prob) in enumerate(zip(requests, ensemble_probs)):
                individual_scores = {
                    name: float(pred.cpu().numpy()[i]) 
                    for name, pred in individual_preds_batch.items()
                }
                
                confidence_threshold = self._calculate_adaptive_threshold(individual_scores)
                is_anomaly = ensemble_prob > confidence_threshold
                
                attack_type, attack_confidence = self._classify_advanced_attack_type(
                    request, features_batch[i], individual_scores
                )
                
                result = {
                    'is_anomaly': is_anomaly,
                    'confidence': float(ensemble_prob),
                    'attack_type': attack_type,
                    'attack_confidence': attack_confidence,
                    'model_scores': individual_scores,
                    'model_type': 'advanced_ensemble_batch'
                }
                
                results.append(result)
            
        except Exception as e:
            logger.error(f"Batch prediction error: {e}")
            results = [{'error': str(e)} for _ in requests]
        
        return results
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        
        avg_inference_time = (self.total_inference_time / self.inference_count 
                            if self.inference_count > 0 else 0)
        
        return {
            'total_inferences': self.inference_count,
            'average_inference_time_ms': avg_inference_time * 1000,
            'throughput_per_second': 1 / avg_inference_time if avg_inference_time > 0 else 0,
            'models_loaded': self.is_loaded,
            'device': str(self.device),
            'model_type': 'advanced_ensemble'
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get detailed model information"""
        
        return {
            'models_loaded': self.is_loaded,
            'ensemble_available': self.ensemble_model is not None,
            'feature_extractor_available': self.feature_extractor is not None,
            'metadata': self.metadata,
            'device': str(self.device),
            'models_directory': str(self.models_dir),
            'performance_stats': self.get_performance_stats(),
            'model_architecture': {
                'lstm_autoencoder': 'Advanced LSTM with attention mechanism',
                'transformer': 'Multi-head attention transformer encoder',
                'cnn': '1D CNN with multi-scale filters',
                'vae': 'Variational autoencoder for anomaly detection',
                'ensemble': 'Neural fusion of all models'
            }
        }

def test_advanced_inference():
    """Test the advanced inference engine"""
    
    print("🧪 Testing Advanced ML Inference Engine")
    print("=" * 50)
    
    # Initialize engine
    engine = AdvancedInferenceEngine()
    
    if not engine.load_models():
        print("❌ Failed to load advanced models")
        print("Please run: python advanced_training_pipeline.py")
        return
    
    # Test requests
    test_requests = [
        {
            'path': '/',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'method': 'GET',
            'country': 'US',
            'ip': '192.168.1.100',
            'timestamp': 1640995200
        },
        {
            'path': "/?id=1' UNION SELECT * FROM users--",
            'user_agent': 'sqlmap/1.6.12',
            'method': 'POST',
            'country': 'CN',
            'ip': '10.0.0.50',
            'timestamp': 1640995260
        },
        {
            'path': '/search?q=<script>alert("XSS")</script>',
            'user_agent': 'Mozilla/5.0',
            'method': 'GET',
            'country': 'RU',
            'ip': '172.16.1.10',
            'timestamp': 1640995320
        }
    ]
    
    print(f"\n🔍 Testing {len(test_requests)} requests...")
    
    for i, request in enumerate(test_requests):
        print(f"\n--- Test {i+1}: {request['path'][:50]}... ---")
        
        result = engine.predict_anomaly(request)
        
        if 'error' in result:
            print(f"❌ Error: {result['error']}")
            continue
        
        print(f"🎯 Results:")
        print(f"   Anomaly: {result['is_anomaly']}")
        print(f"   Confidence: {result['confidence']:.3f}")
        print(f"   Risk Score: {result['risk_score']:.3f}")
        print(f"   Attack Type: {result['attack_type']}")
        print(f"   Attack Confidence: {result['attack_confidence']:.3f}")
        print(f"   Inference Time: {result['inference_time_ms']:.2f}ms")
        
        print(f"📊 Model Scores:")
        for model, score in result['model_scores'].items():
            print(f"   {model}: {score:.3f}")
    
    # Performance stats
    print(f"\n📈 Performance Statistics:")
    stats = engine.get_performance_stats()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Batch test
    print(f"\n🚀 Batch Processing Test:")
    batch_results = engine.batch_predict(test_requests)
    print(f"   Processed {len(batch_results)} requests in batch")
    
    print(f"\n✅ Advanced inference engine testing completed!")

if __name__ == "__main__":
    test_advanced_inference()