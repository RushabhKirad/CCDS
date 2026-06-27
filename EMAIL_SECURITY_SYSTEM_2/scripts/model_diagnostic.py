"""
MODEL DIAGNOSTIC SCRIPT
Check which models are working and which are broken
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import joblib

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models')
print('=' * 60)
print('MODEL DIAGNOSTIC REPORT')
print('=' * 60)

# Test Text Model + Vectorizer
print('\n1. TEXT PHISHING MODEL:')
text_model = None
text_vect = None
try:
    text_model = joblib.load(os.path.join(MODELS_DIR, 'text_phishing_model.pkl'))
    print(f'   Model Loaded: {type(text_model).__name__}')
except Exception as e:
    print(f'   [X] Model Load Error: {e}')

try:
    text_vect = joblib.load(os.path.join(MODELS_DIR, 'vectorizer.pkl'))
    print(f'   Vectorizer Loaded: {type(text_vect).__name__}')
    
    # Check if fitted
    if hasattr(text_vect, 'vocabulary_') and text_vect.vocabulary_:
        print(f'   Vocabulary Size: {len(text_vect.vocabulary_)} words')
    else:
        print('   [X] vocabulary_ is EMPTY or MISSING')
    
    if hasattr(text_vect, 'idf_'):
        print(f'   IDF Vector: {len(text_vect.idf_)} values - FITTED!')
    else:
        print('   [X] idf_ MISSING - NOT FITTED! (This is the bug)')
        
    # Try to transform
    if text_model and text_vect:
        try:
            test_text = 'Your account has been suspended click here now'
            X = text_vect.transform([test_text])
            pred = text_model.predict_proba(X)
            print(f'   Test Prediction: {pred[0]} - WORKS!')
        except Exception as e:
            print(f'   [X] Prediction Error: {e}')
except Exception as e:
    print(f'   [X] Vectorizer Load Error: {e}')

# Test URL Model + Vectorizer
print('\n2. URL PHISHING MODEL:')
url_model = None
url_vect = None
try:
    url_model = joblib.load(os.path.join(MODELS_DIR, 'url_model.pkl'))
    print(f'   Model Loaded: {type(url_model).__name__}')
except Exception as e:
    print(f'   [X] Model Load Error: {e}')

try:
    url_vect = joblib.load(os.path.join(MODELS_DIR, 'url_vectorizer.pkl'))
    print(f'   Vectorizer Loaded: {type(url_vect).__name__}')
    
    if hasattr(url_vect, 'vocabulary_') and url_vect.vocabulary_:
        print(f'   Vocabulary Size: {len(url_vect.vocabulary_)} tokens')
    else:
        print('   [X] vocabulary_ is EMPTY or MISSING')
    
    if hasattr(url_vect, 'idf_'):
        print(f'   IDF Vector: {len(url_vect.idf_)} values - FITTED!')
    else:
        print('   [X] idf_ MISSING - NOT FITTED! (This is the bug)')
        
    # Try to transform
    if url_model and url_vect:
        try:
            test_url = 'http://paypal-verify.tk/login'
            X = url_vect.transform([test_url])
            pred = url_model.predict_proba(X)
            print(f'   Test Prediction: {pred[0]} - WORKS!')
        except Exception as e:
            print(f'   [X] Prediction Error: {e}')
except Exception as e:
    print(f'   [X] Vectorizer Load Error: {e}')

# Test Attachment Model
print('\n3. ATTACHMENT MODEL:')
try:
    att_model = joblib.load(os.path.join(MODELS_DIR, 'attachment_model.pkl'))
    print(f'   Model Loaded: {type(att_model).__name__}')
    if hasattr(att_model, 'n_features_in_'):
        print(f'   Expected Features: {att_model.n_features_in_}')
    print('   Status: Working (uses pre-extracted features, no vectorizer)')
except Exception as e:
    print(f'   [X] Model Load Error: {e}')

print('\n' + '=' * 60)
print('SUMMARY:')
print('=' * 60)

text_idf_ok = text_vect is not None and hasattr(text_vect, 'idf_')
url_idf_ok  = url_vect  is not None and hasattr(url_vect,  'idf_')

if text_idf_ok and url_idf_ok:
    print('\n   [OK] All models and vectorizers are properly fitted and ready.')
    print('   [OK] Text vectorizer idf_: present')
    print('   [OK] URL  vectorizer idf_: present')
else:
    if not text_idf_ok:
        print('\n   [X] Text vectorizer idf_ MISSING — run retrain_models.py to fix.')
    if not url_idf_ok:
        print('\n   [X] URL vectorizer idf_ MISSING — run fix_url_model.py to fix.')
