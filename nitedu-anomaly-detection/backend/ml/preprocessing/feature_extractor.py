import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class NetworkFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            'packet_count', 'byte_count', 'duration', 'packets_per_second',
            'bytes_per_second', 'avg_packet_size', 'port_entropy', 'ip_entropy',
            'protocol_diversity', 'time_interval', 'sql_injection_score',
            'xss_score', 'ddos_score', 'bot_score', 'geo_anomaly'
        ]
    
    def extract_features(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """Extract features from network events"""
        if not events:
            return np.zeros((1, len(self.feature_names)))
        
        features = []
        for event in events:
            feature_vector = self._extract_single_event_features(event)
            features.append(feature_vector)
        
        return np.array(features)
    
    def _extract_single_event_features(self, event: Dict[str, Any]) -> List[float]:
        """Extract features from a single network event"""
        features = []
        
        # Basic traffic metrics
        features.append(float(event.get('packet_count', 0)))
        features.append(float(event.get('byte_count', 0)))
        features.append(float(event.get('duration', 0)))
        
        # Derived metrics
        packet_count = event.get('packet_count', 1)
        byte_count = event.get('byte_count', 0)
        duration = max(event.get('duration', 1), 0.001)  # Avoid division by zero
        
        features.append(packet_count / duration)  # packets_per_second
        features.append(byte_count / duration)    # bytes_per_second
        features.append(byte_count / max(packet_count, 1))  # avg_packet_size
        
        # Entropy features
        features.append(self._calculate_port_entropy(event))
        features.append(self._calculate_ip_entropy(event))
        features.append(self._calculate_protocol_diversity(event))
        
        # Temporal feature
        features.append(self._extract_time_feature(event.get('timestamp')))
        
        # Enhanced cyber security features
        features.append(self._calculate_sql_injection_score(event.get('path', '')))
        features.append(self._calculate_xss_score(event.get('path', '')))
        features.append(self._calculate_ddos_score(event))
        features.append(self._calculate_bot_score(event.get('user_agent', '')))
        features.append(self._calculate_geo_anomaly(event.get('country', '')))
        
        return features
    
    def _calculate_port_entropy(self, event: Dict[str, Any]) -> float:
        """Calculate entropy of port usage"""
        ports = []
        if 'src_port' in event:
            ports.append(event['src_port'])
        if 'dst_port' in event:
            ports.append(event['dst_port'])
        
        if not ports:
            return 0.0
        
        return self._entropy(ports)
    
    def _calculate_ip_entropy(self, event: Dict[str, Any]) -> float:
        """Calculate entropy of IP addresses"""
        ips = []
        if 'src_ip' in event:
            ips.append(event['src_ip'])
        if 'dst_ip' in event:
            ips.append(event['dst_ip'])
        
        if not ips:
            return 0.0
        
        return self._entropy(ips)
    
    def _calculate_protocol_diversity(self, event: Dict[str, Any]) -> float:
        """Calculate protocol diversity score"""
        protocol = event.get('protocol', 'unknown')
        # Simple protocol scoring (can be enhanced)
        protocol_scores = {
            'tcp': 0.3, 'udp': 0.2, 'icmp': 0.1, 
            'http': 0.4, 'https': 0.5, 'dns': 0.3,
            'unknown': 0.0
        }
        return protocol_scores.get(protocol.lower(), 0.0)
    
    def _extract_time_feature(self, timestamp: Any) -> float:
        """Extract time-based feature (hour of day normalized)"""
        if timestamp is None:
            return 0.0
        
        try:
            if isinstance(timestamp, str):
                dt = pd.to_datetime(timestamp)
            elif isinstance(timestamp, (int, float)):
                dt = pd.to_datetime(timestamp, unit='s')
            else:
                dt = timestamp
            
            # Normalize hour to [0, 1]
            return dt.hour / 24.0
        except:
            return 0.0
    
    def _entropy(self, values: List[Any]) -> float:
        """Calculate Shannon entropy"""
        if not values:
            return 0.0
        
        value_counts = pd.Series(values).value_counts()
        probabilities = value_counts / len(values)
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    def create_sequences(self, features: np.ndarray, sequence_length: int = 10,
                        step_size: int = 1) -> Tuple[np.ndarray, np.ndarray]:
        """Create sequences for LSTM and aggregated features for Isolation Forest"""
        if len(features) < sequence_length:
            # Pad with zeros if not enough data
            padding = np.zeros((sequence_length - len(features), features.shape[1]))
            features = np.vstack([padding, features])
        
        sequences = []
        aggregated_features = []
        
        for i in range(0, len(features) - sequence_length + 1, step_size):
            sequence = features[i:i + sequence_length]
            sequences.append(sequence)
            
            # Aggregate features for Isolation Forest
            agg_features = np.concatenate([
                np.mean(sequence, axis=0),
                np.std(sequence, axis=0),
                np.max(sequence, axis=0) - np.min(sequence, axis=0)  # range
            ])
            aggregated_features.append(agg_features)
        
        return np.array(sequences), np.array(aggregated_features)
    
    def _calculate_sql_injection_score(self, path: str) -> float:
        """Detect SQL injection patterns"""
        if not path:
            return 0.0
        
        sql_patterns = [
            r'union.*select', r'drop.*table', r'insert.*into', r'delete.*from',
            r'update.*set', r'exec\(', r'sp_executesql', r'xp_cmdshell',
            r'\bor\b.*=.*\bor\b', r'\band\b.*=.*\band\b', r"'.*or.*'.*='.*'"
        ]
        
        import re
        score = 0.0
        path_lower = path.lower()
        for pattern in sql_patterns:
            if re.search(pattern, path_lower):
                score += 1.0
        
        return min(score / len(sql_patterns), 1.0)
    
    def _calculate_xss_score(self, path: str) -> float:
        """Detect XSS attack patterns"""
        if not path:
            return 0.0
        
        import re
        xss_patterns = [
            r'<script', r'javascript:', r'onerror=', r'onload=', r'onclick=',
            r'alert\(', r'document\.cookie', r'window\.location', r'eval\(',
            r'fromcharcode', r'<iframe', r'<object', r'<embed'
        ]
        
        score = 0.0
        path_lower = path.lower()
        for pattern in xss_patterns:
            if re.search(pattern, path_lower):
                score += 1.0
        
        return min(score / len(xss_patterns), 1.0)
    
    def _calculate_ddos_score(self, event: Dict[str, Any]) -> float:
        """Calculate DDoS likelihood score"""
        score = 0.0
        
        # High packet rate
        pps = event.get('packets_per_second', 0)
        if pps > 1000:
            score += 0.4
        elif pps > 500:
            score += 0.2
        
        # Large byte count
        byte_count = event.get('byte_count', 0)
        if byte_count > 1000000:  # 1MB
            score += 0.3
        
        # Short duration with high traffic
        duration = event.get('duration', 1)
        if duration < 1 and pps > 100:
            score += 0.3
        
        return min(score, 1.0)
    
    def _calculate_bot_score(self, user_agent: str) -> float:
        """Calculate bot likelihood score"""
        if not user_agent:
            return 1.0
        
        bot_indicators = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python', 'java', 'go-http', 'okhttp', 'automated'
        ]
        
        ua_lower = user_agent.lower()
        score = sum(1 for indicator in bot_indicators if indicator in ua_lower)
        
        return min(score / len(bot_indicators), 1.0)
    
    def _calculate_geo_anomaly(self, country: str) -> float:
        """Calculate geographic anomaly score"""
        if not country:
            return 0.5
        
        # High-risk countries (simplified example)
        high_risk = ['XX', 'ZZ', 'CN', 'RU', 'KP']
        medium_risk = ['IR', 'PK', 'BD']
        
        if country in high_risk:
            return 0.8
        elif country in medium_risk:
            return 0.4
        
        return 0.1