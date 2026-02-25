"""
COMPREHENSIVE ML MODEL DIAGNOSTIC SCRIPT
Tests all models in the Email Security System
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 70)
print("EMAIL SECURITY SYSTEM - ML MODEL DIAGNOSTICS")
print("=" * 70)

# ============================================================================
# STEP 1: CHECK MODEL FILES
# ============================================================================
print("\n[STEP 1] CHECKING MODEL FILES")
print("-" * 50)

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
expected_models = {
    'text_phishing_model.pkl': 'Text Phishing Classifier',
    'vectorizer.pkl': 'Text TF-IDF Vectorizer',
    'url_model.pkl': 'URL Phishing Classifier',
    'url_vectorizer.pkl': 'URL TF-IDF Vectorizer',
    'attachment_model.pkl': 'Attachment Risk Classifier'
}

for filename, description in expected_models.items():
    filepath = os.path.join(MODELS_DIR, filename)
    if os.path.exists(filepath):
        size = os.path.getsize(filepath)
        print(f"  [OK] {filename} ({size:,} bytes) - {description}")
    else:
        print(f"  [X] {filename} - MISSING! ({description})")

# ============================================================================
# STEP 2: LOAD MODELS WITH JOBLIB
# ============================================================================
print("\n[STEP 2] LOADING MODELS")
print("-" * 50)

import joblib

models = {}
try:
    # Text model
    text_model_path = os.path.join(MODELS_DIR, 'text_phishing_model.pkl')
    models['text_model'] = joblib.load(text_model_path)
    print(f"  [OK] Text Model: {type(models['text_model']).__name__}")
except Exception as e:
    print(f"  [X] Text Model: {e}")

try:
    # Text vectorizer
    text_vect_path = os.path.join(MODELS_DIR, 'vectorizer.pkl')
    models['text_vect'] = joblib.load(text_vect_path)
    print(f"  [OK] Text Vectorizer: {type(models['text_vect']).__name__}")
    
    # Check if vectorizer is fitted
    if hasattr(models['text_vect'], 'vocabulary_'):
        vocab_size = len(models['text_vect'].vocabulary_)
        print(f"       Vocabulary size: {vocab_size} words")
    else:
        print(f"       [!] Vectorizer has no vocabulary_ - NOT FITTED!")
        
    if hasattr(models['text_vect'], 'idf_'):
        print(f"       IDF vector: {len(models['text_vect'].idf_)} values")
    else:
        print(f"       [!] Vectorizer has no idf_ - TF-IDF NOT FITTED!")
        
except Exception as e:
    print(f"  [X] Text Vectorizer: {e}")

try:
    # URL model
    url_model_path = os.path.join(MODELS_DIR, 'url_model.pkl')
    models['url_model'] = joblib.load(url_model_path)
    print(f"  [OK] URL Model: {type(models['url_model']).__name__}")
except Exception as e:
    print(f"  [X] URL Model: {e}")

try:
    # URL vectorizer
    url_vect_path = os.path.join(MODELS_DIR, 'url_vectorizer.pkl')
    models['url_vect'] = joblib.load(url_vect_path)
    print(f"  [OK] URL Vectorizer: {type(models['url_vect']).__name__}")
    
    if hasattr(models['url_vect'], 'vocabulary_'):
        vocab_size = len(models['url_vect'].vocabulary_)
        print(f"       Vocabulary size: {vocab_size} tokens")
    else:
        print(f"       [!] URL Vectorizer has no vocabulary_ - NOT FITTED!")
        
except Exception as e:
    print(f"  [X] URL Vectorizer: {e}")

try:
    # Attachment model
    att_model_path = os.path.join(MODELS_DIR, 'attachment_model.pkl')
    models['attachment_model'] = joblib.load(att_model_path)
    print(f"  [OK] Attachment Model: {type(models['attachment_model']).__name__}")
except Exception as e:
    print(f"  [X] Attachment Model: {e}")

# ============================================================================
# STEP 3: TEST PREDICTIONS
# ============================================================================
print("\n[STEP 3] TESTING PREDICTIONS")
print("-" * 50)

# Test text samples
test_samples = [
    {
        'text': 'Your account has been suspended. Click here to verify: http://fake.com/login',
        'expected': 'phishing'
    },
    {
        'text': 'Hi there! Just wanted to check how you are doing. Hope everything is well!',
        'expected': 'safe'
    },
    {
        'text': 'URGENT: Your bank account will be closed. Enter your PIN and SSN immediately!',
        'expected': 'phishing'
    },
    {
        'text': 'Here are the meeting notes from yesterday. Let me know if you have questions.',
        'expected': 'safe'
    }
]

print("\n  Testing Text Classifier:")
if 'text_model' in models and 'text_vect' in models:
    try:
        for i, sample in enumerate(test_samples, 1):
            text_vector = models['text_vect'].transform([sample['text']])
            prediction = models['text_model'].predict(text_vector)[0]
            
            # Get probability if available
            if hasattr(models['text_model'], 'predict_proba'):
                proba = models['text_model'].predict_proba(text_vector)[0]
                if len(proba) > 1:
                    confidence = max(proba)
                else:
                    confidence = proba[0]
            else:
                confidence = 0
            
            # Map numeric prediction to label if needed
            if isinstance(prediction, (int, float)):
                if prediction == 1:
                    label = 'phishing'
                else:
                    label = 'safe'
            else:
                label = str(prediction).lower()
            
            status = "[OK]" if label == sample['expected'] else "[X]"
            print(f"    {status} Sample {i}: Predicted={label.upper():8} Expected={sample['expected'].upper():8} Conf={confidence:.2f}")
            print(f"        Text: {sample['text'][:50]}...")
    except Exception as e:
        print(f"    [X] Text prediction error: {e}")
else:
    print("    [X] Text model/vectorizer not loaded")

# Test URL samples
print("\n  Testing URL Classifier:")
url_samples = [
    {'url': 'http://paypal-verify.tk/login', 'expected': 'phishing'},
    {'url': 'https://www.google.com', 'expected': 'safe'},
    {'url': 'http://192.168.1.1/admin/verify', 'expected': 'phishing'},
    {'url': 'https://github.com/user/repo', 'expected': 'safe'}
]

if 'url_model' in models and 'url_vect' in models:
    try:
        for i, sample in enumerate(url_samples, 1):
            url_vector = models['url_vect'].transform([sample['url']])
            prediction = models['url_model'].predict(url_vector)[0]
            
            if hasattr(models['url_model'], 'predict_proba'):
                proba = models['url_model'].predict_proba(url_vector)[0]
                confidence = max(proba) if len(proba) > 1 else proba[0]
            else:
                confidence = 0
            
            if isinstance(prediction, (int, float)):
                label = 'phishing' if prediction == 1 else 'safe'
            else:
                label = str(prediction).lower()
            
            status = "[OK]" if label == sample['expected'] else "[X]"
            print(f"    {status} Sample {i}: Predicted={label.upper():8} URL={sample['url'][:40]}")
    except Exception as e:
        print(f"    [X] URL prediction error: {e}")
else:
    print("    [X] URL model/vectorizer not loaded")

# ============================================================================
# STEP 4: CHECK HYBRID ANALYSIS CODE
# ============================================================================
print("\n[STEP 4] CHECKING HYBRID ANALYSIS INTEGRATION")
print("-" * 50)

try:
    from hybrid_analysis import hybrid_analyze_email
    print("  [OK] hybrid_analyze_email function imported")
except Exception as e:
    print(f"  [X] Could not import hybrid_analyze_email: {e}")

try:
    from backend.analyzers.model_loader import ModelLoader
    loader = ModelLoader()
    print("  [OK] ModelLoader works correctly")
    print(f"       text_model: {type(loader.text_model).__name__}")
    print(f"       text_vect: {type(loader.text_vect).__name__}")
    print(f"       url_model: {type(loader.url_model).__name__}")
    print(f"       url_vect: {type(loader.url_vect).__name__}")
    print(f"       attachment_model: {type(loader.attachment_model).__name__}")
except Exception as e:
    print(f"  [X] ModelLoader error: {e}")

# ============================================================================
# STEP 5: FULL PREDICTION TEST
# ============================================================================
print("\n[STEP 5] FULL HYBRID ANALYSIS TEST")
print("-" * 50)

try:
    from backend.db.db_utils import execute_query, fetch_one, fetch_all
    from backend.analyzers.model_loader import ModelLoader
    from hybrid_analysis import hybrid_analyze_email
    
    loader = ModelLoader()
    
    # Insert a test email
    test_email = {
        'sender': 'test@phishing-test.ml',
        'subject': 'URGENT: Verify your account NOW',
        'body': 'Your account will be suspended. Click here: http://verify-account.tk/login to enter your password and SSN.'
    }
    
    user_email = 'test@diagnostic.com'
    
    # Insert
    execute_query(
        "INSERT INTO emails (sender, subject, body, user_email, is_read, created_at, label) VALUES (%s, %s, %s, %s, 0, NOW(), 'pending')",
        (test_email['sender'], test_email['subject'], test_email['body'], user_email)
    )
    
    # Get ID
    email_record = fetch_one(
        "SELECT id FROM emails WHERE sender = %s ORDER BY id DESC LIMIT 1",
        (test_email['sender'],)
    )
    
    if email_record:
        email_id = email_record['id']
        print(f"  Created test email with ID: {email_id}")
        
        # Run hybrid analysis
        print("  Running hybrid analysis...")
        label, confidence = hybrid_analyze_email(email_id, test_email['body'], test_email['subject'], loader)
        
        print(f"\n  RESULT: {label.upper()} (Confidence: {confidence*100:.1f}%)")
        print(f"  Expected: PHISHING")
        
        if label == 'phishing':
            print("  [OK] Phishing correctly detected!")
        else:
            print("  [X] Detection FAILED - This phishing email was marked as safe")
        
        # Clean up
        execute_query("DELETE FROM emails WHERE id = %s", (email_id,))
        print(f"  Cleaned up test email")
    else:
        print("  [X] Could not insert test email")
        
except Exception as e:
    print(f"  [X] Full test error: {e}")
    import traceback
    traceback.print_exc()

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 70)
print("DIAGNOSTIC SUMMARY")
print("=" * 70)
print("""
If predictions are failing, possible issues:
1. Vectorizer not fitted (idf_ missing) - RETRAIN REQUIRED
2. Model/Vectorizer mismatch - they were trained separately  
3. Wrong prediction labels (numeric vs string)
4. Threshold too high in hybrid_analysis.py (currently 0.6)

To fix: Run the training scripts in backend/analyzers/
""")
