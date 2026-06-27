import os
import json
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
from datetime import datetime

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
PROCESSED_DIR = os.path.join(BASE_DIR, 'processed')
CACHE_FILE = os.path.join(BASE_DIR, 'evaluation_results.json')


class RealEvaluator:

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.results = None
        
    def load_model(self):
        """Load trained model and vectorizer"""
        model_path = os.path.join(MODELS_DIR, 'text_phishing_model.pkl')
        vectorizer_path = os.path.join(MODELS_DIR, 'vectorizer.pkl')
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        if not os.path.exists(vectorizer_path):
            raise FileNotFoundError(f"Vectorizer not found: {vectorizer_path}")
            
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        print(f"[OK] Loaded model: {type(self.model).__name__}")
        print(f"[OK] Loaded vectorizer: {type(self.vectorizer).__name__}")
        
    def load_test_data(self):
        """Load test dataset"""
        X_test_path = os.path.join(PROCESSED_DIR, 'X_test.csv')
        y_test_path = os.path.join(PROCESSED_DIR, 'y_test.csv')
        
        if not os.path.exists(X_test_path):
            raise FileNotFoundError(f"Test data not found: {X_test_path}")
            
        X_test = pd.read_csv(X_test_path)
        y_test = pd.read_csv(y_test_path)
        
        # Handle column names
        text_col = X_test.columns[0]
        label_col = y_test.columns[0]
        
        X_texts = X_test[text_col].fillna('').astype(str).values
        y_true = y_test[label_col].values
        
        print(f"[OK] Loaded {len(X_texts)} test samples")
        print(f"[OK] Label distribution: {np.bincount(y_true)}")
        
        return X_texts, y_true
    
    def load_training_data(self):
        """Load training dataset for vectorizer fitting"""
        X_train_path = os.path.join(PROCESSED_DIR, 'X_train.csv')
        y_train_path = os.path.join(PROCESSED_DIR, 'y_train.csv')
        
        X_train = pd.read_csv(X_train_path)
        y_train = pd.read_csv(y_train_path)
        
        text_col = X_train.columns[0]
        label_col = y_train.columns[0]
        
        X_texts = X_train[text_col].fillna('').astype(str).values
        y_true = y_train[label_col].values
        
        return X_texts, y_true
        
    def evaluate(self, force_recompute=False):
        """Run full evaluation on test set"""
        
        # Check cache first
        if not force_recompute and os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, 'r') as f:
                self.results = json.load(f)
                print(f"[OK] Loaded cached results from {CACHE_FILE}")
                return self.results
        
        print("\n" + "="*50)
        print(" MODEL EVALUATION ")
        print("="*50)
        
        # Load data
        X_train, y_train = self.load_training_data()
        X_test, y_test = self.load_test_data()
        
        print(f"\n[...] Training fresh vectorizer on {len(X_train)} samples...")
        
        # Train fresh TF-IDF vectorizer and model
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.naive_bayes import MultinomialNB
        
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        X_train_features = self.vectorizer.fit_transform(X_train)
        X_test_features = self.vectorizer.transform(X_test)
        
        print(f"[OK] Vectorizer fitted with {len(self.vectorizer.vocabulary_)} features")
        
        print("[...] Training Naive Bayes classifier...")
        self.model = MultinomialNB()
        self.model.fit(X_train_features, y_train)
        print(f"[OK] Model trained: {type(self.model).__name__}")
        
        # Get predictions
        print("[...] Running model predictions on test set...")
        y_pred = self.model.predict(X_test_features)
        
        # Get probabilities
        y_proba = self.model.predict_proba(X_test_features)[:, 1]
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)
        
        # AUC-ROC
        auc_roc = None
        try:
            auc_roc = roc_auc_score(y_test, y_proba)
        except:
            pass
        
        # Store results
        self.results = {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "auc_roc": round(auc_roc, 4) if auc_roc else None,
            "confusion_matrix": cm.tolist(),
            "total_samples": len(y_test),
            "positive_samples": int(np.sum(y_test)),
            "negative_samples": int(len(y_test) - np.sum(y_test)),
            "true_positives": int(cm[1][1]) if len(cm) > 1 else 0,
            "true_negatives": int(cm[0][0]),
            "false_positives": int(cm[0][1]) if len(cm[0]) > 1 else 0,
            "false_negatives": int(cm[1][0]) if len(cm) > 1 else 0,
            "training_samples": len(y_train),
            "computed_at": datetime.now().isoformat(),
            "model_type": type(self.model).__name__,
            "vectorizer_type": type(self.vectorizer).__name__,
            "note": "All metrics computed from real model predictions on held-out test set"
        }
        
        # Save to cache
        with open(CACHE_FILE, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n[OK] Results saved to {CACHE_FILE}")
        
        return self.results
    
    def print_report(self):
        """Print formatted evaluation report"""
        if self.results is None:
            self.evaluate()
            
        r = self.results
        print("\n" + "="*50)
        print("       FINAL EVALUATION REPORT ")
        print("="*50)
        print(f"Total Test Samples:    {r['total_samples']}")
        print(f"  - Safe (0):          {r['negative_samples']}")
        print(f"  - Phishing (1):      {r['positive_samples']}")
        print("-" * 50)
        print(f"✅ ACCURACY:           {r['accuracy']*100:.2f}%")
        print(f"✅ PRECISION:          {r['precision']*100:.2f}%")
        print(f"✅ RECALL:             {r['recall']*100:.2f}%")
        print(f"✅ F1-SCORE:           {r['f1_score']*100:.2f}%")
        if r['auc_roc']:
            print(f"✅ AUC-ROC:            {r['auc_roc']:.4f}")
        print("-" * 50)
        print("CONFUSION MATRIX:")
        print(f"                    Predicted Safe | Predicted Phishing")
        print(f"  Actual Safe       {r['true_negatives']:^14} | {r['false_positives']:^18}")
        print(f"  Actual Phishing   {r['false_negatives']:^14} | {r['true_positives']:^18}")
        print("=" * 50)
        print(f"\nComputed at: {r['computed_at']}")
        print(f"Model: {r['model_type']}")
        print("NOTE: All values computed from real predictions.")
        print("=" * 50)


def get_cached_metrics():
    """Get cached metrics or compute if not available"""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    else:
        evaluator = RealEvaluator()
        return evaluator.evaluate()


def get_metrics_for_api():
    """Get metrics formatted for API response (compatible with old format)"""
    metrics = get_cached_metrics()
    return {
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1_score": metrics["f1_score"],
        "confusion_matrix": metrics["confusion_matrix"],
        "ablation": {
            "Note": "Run ablation_study.py for component analysis"
        }
    }


if __name__ == "__main__":
    evaluator = RealEvaluator()
    evaluator.evaluate(force_recompute=True)
    evaluator.print_report()
