import numpy as np
from collections import deque
from typing import Dict, Tuple
import logging

logger = logging.getLogger(__name__)

class OnlineLearningDetector:
    def __init__(self, window_size: int = 1000, adaptation_rate: float = 0.1):
        self.window_size = window_size
        self.adaptation_rate = adaptation_rate
        
        # Sliding window for recent data
        self.recent_features = deque(maxlen=window_size)
        self.recent_scores = deque(maxlen=window_size)
        
        # Adaptive thresholds
        self.threshold = 0.5
        self.score_mean = 0.0
        self.score_std = 1.0
        
    def update(self, features: np.ndarray, scores: np.ndarray, 
               feedback: np.ndarray = None):
        """Update model with new data and optional feedback"""
        
        # Add to sliding window
        for feat, score in zip(features, scores):
            self.recent_features.append(feat)
            self.recent_scores.append(score)
        
        # Update statistics
        if len(self.recent_scores) > 10:
            recent_array = np.array(self.recent_scores)
            new_mean = np.mean(recent_array)
            new_std = np.std(recent_array)
            
            # Exponential moving average
            self.score_mean = (1 - self.adaptation_rate) * self.score_mean + \
                             self.adaptation_rate * new_mean
            self.score_std = (1 - self.adaptation_rate) * self.score_std + \
                            self.adaptation_rate * new_std
            
            # Adaptive threshold
            self.threshold = self.score_mean + 2 * self.score_std
        
        # Process feedback if available
        if feedback is not None:
            self._process_feedback(scores, feedback)
    
    def _process_feedback(self, scores: np.ndarray, feedback: np.ndarray):
        """Adjust threshold based on feedback"""
        false_positives = (scores > self.threshold) & (feedback == 0)
        false_negatives = (scores <= self.threshold) & (feedback == 1)
        
        if np.any(false_positives):
            self.threshold *= 1.1  # Increase threshold
        if np.any(false_negatives):
            self.threshold *= 0.9  # Decrease threshold
    
    def get_adaptive_threshold(self) -> float:
        return self.threshold