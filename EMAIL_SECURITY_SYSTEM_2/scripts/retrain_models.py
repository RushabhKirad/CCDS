"""
RETRAIN ML MODELS
This script retrains the text and URL models with proper TF-IDF vectorizers
"""
import os
import sys
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score
import re

# Set paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')
PROCESSED_DIR = os.path.join(BASE_DIR, 'processed')

print("=" * 60)
print("RETRAINING ML MODELS")
print("=" * 60)

# ============================================================================
# STEP 1: RETRAIN TEXT PHISHING MODEL
# ============================================================================
print("\n[STEP 1] RETRAINING TEXT PHISHING MODEL")
print("-" * 50)

# Load training data
X_train = pd.read_csv(os.path.join(PROCESSED_DIR, 'X_train.csv'))['text'].fillna('').astype(str)
y_train = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_train.csv'))['label']
X_test = pd.read_csv(os.path.join(PROCESSED_DIR, 'X_test.csv'))['text'].fillna('').astype(str)
y_test = pd.read_csv(os.path.join(PROCESSED_DIR, 'y_test.csv'))['label']

print(f"   Training samples: {len(X_train)}")
print(f"   Test samples: {len(X_test)}")
print(f"   Labels: {y_train.unique()}")

# Create and fit TF-IDF vectorizer
print("   Creating TF-IDF vectorizer...")
text_vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 2),
    stop_words='english',
    min_df=2,
    max_df=0.9
)

# IMPORTANT: fit_transform creates the IDF values
X_train_tfidf = text_vectorizer.fit_transform(X_train)
X_test_tfidf = text_vectorizer.transform(X_test)

print(f"   Vocabulary size: {len(text_vectorizer.vocabulary_)}")
print(f"   IDF fitted: {hasattr(text_vectorizer, 'idf_') and len(text_vectorizer.idf_) > 0}")

# Train classifier
print("   Training RandomForest classifier...")
text_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
text_model.fit(X_train_tfidf, y_train)

# Evaluate
y_pred = text_model.predict(X_test_tfidf)
accuracy = accuracy_score(y_test, y_pred)
print(f"   Accuracy: {accuracy:.4f}")
print(f"\n{classification_report(y_test, y_pred)}")

# Save models
text_model_path = os.path.join(MODELS_DIR, 'text_phishing_model.pkl')
text_vect_path = os.path.join(MODELS_DIR, 'vectorizer.pkl')

joblib.dump(text_model, text_model_path)
joblib.dump(text_vectorizer, text_vect_path)
print(f"   Saved: {text_model_path}")
print(f"   Saved: {text_vect_path}")

# ============================================================================
# STEP 2: RETRAIN URL PHISHING MODEL
# ============================================================================
print("\n[STEP 2] RETRAINING URL PHISHING MODEL")
print("-" * 50)

# Extract URLs from text for URL model training
def extract_urls(text):
    """Extract URLs from text"""
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(text))
    return ' '.join(urls) if urls else ''

# Create URL training data from existing text data
print("   Extracting URLs from text data...")
url_texts = X_train.apply(extract_urls)
url_labels = y_train

# Filter to only samples with URLs
has_urls = url_texts.str.len() > 0
url_train_data = url_texts[has_urls].tolist()
url_train_labels = url_labels[has_urls].tolist()

print(f"   Samples with URLs: {len(url_train_data)}")

if len(url_train_data) > 100:
    # Create URL vectorizer
    url_vectorizer = TfidfVectorizer(
        max_features=3000,
        ngram_range=(1, 3),
        analyzer='char_wb',  # Character-level for URL analysis
        min_df=1
    )
    
    X_url_tfidf = url_vectorizer.fit_transform(url_train_data)
    
    print(f"   URL Vocabulary size: {len(url_vectorizer.vocabulary_)}")
    print(f"   URL IDF fitted: {hasattr(url_vectorizer, 'idf_') and len(url_vectorizer.idf_) > 0}")
    
    # Train URL classifier
    url_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    url_model.fit(X_url_tfidf, url_train_labels)
    
    # Save URL models
    url_model_path = os.path.join(MODELS_DIR, 'url_model.pkl')
    url_vect_path = os.path.join(MODELS_DIR, 'url_vectorizer.pkl')
    
    joblib.dump(url_model, url_model_path)
    joblib.dump(url_vectorizer, url_vect_path)
    print(f"   Saved: {url_model_path}")
    print(f"   Saved: {url_vect_path}")
else:
    print("   [!] Not enough URL samples to train URL model")
    print("   [!] Creating a simple URL vectorizer anyway...")
    
    # Create a simple URL vectorizer with sample data
    sample_urls = [
        'http://google.com', 'http://facebook.com', 'http://amazon.com',
        'http://paypal-verify.tk/login', 'http://192.168.1.1/admin',
        'http://bit.ly/scam', 'http://secure-bank.ml/verify'
    ]
    sample_labels = [0, 0, 0, 1, 1, 1, 1]  # 0=safe, 1=phishing
    
    url_vectorizer = TfidfVectorizer(
        max_features=3000,
        ngram_range=(1, 3),
        analyzer='char_wb',
        min_df=1
    )
    X_url = url_vectorizer.fit_transform(sample_urls)
    
    url_model = RandomForestClassifier(n_estimators=10, random_state=42)
    url_model.fit(X_url, sample_labels)
    
    url_model_path = os.path.join(MODELS_DIR, 'url_model.pkl')
    url_vect_path = os.path.join(MODELS_DIR, 'url_vectorizer.pkl')
    
    joblib.dump(url_model, url_model_path)
    joblib.dump(url_vectorizer, url_vect_path)
    print(f"   Saved: {url_model_path}")
    print(f"   Saved: {url_vect_path}")

# ============================================================================
# STEP 3: VERIFY MODELS
# ============================================================================
print("\n[STEP 3] VERIFYING MODELS")
print("-" * 50)

# Reload and test
text_model = joblib.load(os.path.join(MODELS_DIR, 'text_phishing_model.pkl'))
text_vect = joblib.load(os.path.join(MODELS_DIR, 'vectorizer.pkl'))
url_model = joblib.load(os.path.join(MODELS_DIR, 'url_model.pkl'))
url_vect = joblib.load(os.path.join(MODELS_DIR, 'url_vectorizer.pkl'))

# Test text model
test_texts = [
    "Your account has been suspended. Click here to verify immediately.",
    "Hi, just wanted to check on the meeting tomorrow.",
    "URGENT: Your bank account will be closed in 24 hours! Enter PIN now.",
    "Here are the project files as requested. Let me know if you have questions."
]

print("   Testing text model:")
for text in test_texts:
    X = text_vect.transform([text])
    pred = text_model.predict(X)[0]
    proba = text_model.predict_proba(X)[0]
    label = 'PHISHING' if pred == 1 else 'SAFE'
    print(f"   [{label}] {proba} - {text[:50]}...")

# Test URL model
test_urls = [
    "http://paypal-verify.tk/login",
    "https://www.google.com",
    "http://192.168.1.1/admin/verify"
]

print("\n   Testing URL model:")
for url in test_urls:
    X = url_vect.transform([url])
    pred = url_model.predict(X)[0]
    proba = url_model.predict_proba(X)[0]
    label = 'PHISHING' if pred == 1 else 'SAFE'
    print(f"   [{label}] {proba} - {url}")

print("\n" + "=" * 60)
print("RETRAINING COMPLETE!")
print("=" * 60)
