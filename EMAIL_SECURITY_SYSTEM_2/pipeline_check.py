"""
Full Pipeline Diagnostic: Database → Ingestion → ML Analysis → Result
Tests every stage of the email processing pipeline end-to-end.
"""
import sys, os, traceback, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PASS = "[OK]"
FAIL = "[X]"
WARN = "[!]"
SEP  = "=" * 70
sep  = "-" * 50

results = []

def check(label, ok, detail=""):
    sym = PASS if ok else FAIL
    msg = f"  {sym} {label}" + (f" — {detail}" if detail else "")
    print(msg)
    results.append((label, ok))
    return ok

print(SEP)
print("  FULL PIPELINE DIAGNOSTIC")
print(f"  {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
print(SEP)

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 1: DATABASE CONNECTION
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 1: DATABASE CONNECTION':^70}")
print(sep)

try:
    from backend.db.db_utils import execute_query, fetch_one, fetch_all, get_connection
    conn = get_connection()
    if conn and conn.is_connected():
        check("MySQL connection", True, "Connected")
        conn.close()
    else:
        check("MySQL connection", False, "Could not connect")
except Exception as e:
    check("MySQL connection", False, str(e))

# Verify essential tables exist
for table in ["emails", "users", "logs", "user_credentials"]:
    try:
        row = fetch_one(f"SHOW TABLES LIKE '{table}'")
        check(f"Table '{table}' exists", bool(row))
    except Exception as e:
        check(f"Table '{table}'", False, str(e))

# Count records
try:
    r = fetch_one("SELECT COUNT(*) as n FROM emails")
    total = r['n'] if r else 0
    check(f"Emails table has records", total > 0, f"{total} rows")
except Exception as e:
    check("Email row count", False, str(e))

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 2: MODEL FILES
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 2: MODEL FILES ON DISK':^70}")
print(sep)

MODELS_DIR = os.path.join(os.path.dirname(__file__), 'models')
model_files = {
    'text_phishing_model.pkl': 'Text Classifier',
    'vectorizer.pkl':          'Text TF-IDF Vectorizer',
    'url_model.pkl':           'URL Classifier',
    'url_vectorizer.pkl':      'URL TF-IDF Vectorizer',
    'attachment_model.pkl':    'Attachment Classifier',
}
for fname, desc in model_files.items():
    path = os.path.join(MODELS_DIR, fname)
    if os.path.exists(path):
        size_mb = os.path.getsize(path) / 1_048_576
        check(f"{desc} ({fname})", True, f"{size_mb:.1f} MB")
    else:
        check(f"{desc} ({fname})", False, "FILE MISSING")

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 3: MODEL LOADING
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 3: MODEL LOADING (ModelLoader)':^70}")
print(sep)

model_loader = None
try:
    from backend.analyzers.model_loader import ModelLoader
    model_loader = ModelLoader()
    check("ModelLoader instantiation", True)
    check("text_model loaded",      hasattr(model_loader, 'text_model') and model_loader.text_model is not None,
          type(model_loader.text_model).__name__)
    check("text_vect loaded",       hasattr(model_loader, 'text_vect') and model_loader.text_vect is not None,
          type(model_loader.text_vect).__name__)
    check("url_model loaded",       hasattr(model_loader, 'url_model') and model_loader.url_model is not None,
          type(model_loader.url_model).__name__)
    check("url_vect loaded",        hasattr(model_loader, 'url_vect') and model_loader.url_vect is not None,
          type(model_loader.url_vect).__name__)
    check("attachment_model loaded",hasattr(model_loader, 'attachment_model') and model_loader.attachment_model is not None,
          type(model_loader.attachment_model).__name__)
except Exception as e:
    check("ModelLoader", False, str(e))
    traceback.print_exc()

# Vectorizer fitted check
try:
    has_vocab = hasattr(model_loader.text_vect, 'vocabulary_')
    has_idf   = hasattr(model_loader.text_vect, 'idf_')
    vocab_size = len(model_loader.text_vect.vocabulary_) if has_vocab else 0
    check("Text vectorizer fitted (vocabulary_)", has_vocab, f"{vocab_size:,} words")
    check("Text vectorizer fitted (idf_)",        has_idf,   f"{len(model_loader.text_vect.idf_):,} values" if has_idf else "MISSING")
except Exception as e:
    check("Vectorizer fit check", False, str(e))

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 4: INDIVIDUAL MODEL PREDICTIONS
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 4: INDIVIDUAL MODEL PREDICTIONS':^70}")
print(sep)

# 4a: Text model
# NOTE: hybrid_analysis.py applies a noise-floor to the raw ML score:
#   effective_score = raw if raw >= 0.65 else raw * 0.5
# So the effective classification threshold is 0.65, not 0.5.
# Borderline safe emails (0.50-0.65) are handled by the false-positive guard.
print("  4a. Text Model:")
text_tests = [
    ("URGENT click verify http://fake.xyz/login enter PIN SSN", "phishing"),
    ("Hi, meeting notes attached. See you tomorrow.", "safe"),
]
if model_loader:
    for txt, expected in text_tests:
        try:
            vec = model_loader.text_vect.transform([txt])
            proba = model_loader.text_model.predict_proba(vec)[0]
            raw_score = proba[1] if len(proba) > 1 else proba[0]
            # Apply same noise-floor as hybrid_analysis.py
            effective_score = raw_score if raw_score >= 0.65 else raw_score * 0.5
            predicted = "phishing" if effective_score >= 0.5 else "safe"
            ok = predicted == expected
            check(f"  Text '{txt[:40]}...'", ok,
                  f"Pred={predicted.upper()} RawScore={raw_score:.3f} EffScore={effective_score:.3f} Exp={expected.upper()}")
        except Exception as e:
            check(f"  Text prediction", False, str(e))

# 4b: URL model
print("  4b. URL Model:")
url_tests = [
    ("http://paypal-verify.tk/login", "phishing"),
    ("https://www.google.com", "safe"),
]
if model_loader:
    for url, expected in url_tests:
        try:
            vec = model_loader.url_vect.transform([url])
            proba = model_loader.url_model.predict_proba(vec)[0]
            phish_score = proba[1] if len(proba) > 1 else proba[0]
            predicted = "phishing" if phish_score >= 0.5 else "safe"
            ok = predicted == expected
            check(f"  URL '{url}'", ok,
                  f"Pred={predicted.upper()} Score={phish_score:.3f} Exp={expected.upper()}")
        except Exception as e:
            check(f"  URL prediction", False, str(e))

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 5: INGESTION (store_email)
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 5: EMAIL INGESTION (save_to_db)':^70}")
print(sep)

test_email_id = None
try:
    from backend.ingestion.save_to_db import store_email
    check("store_email import", True)
    email_data = {
        'sender':     'pipeline-test@phish-diag.ml',
        'receiver':   'test@diagnostic.internal',
        'subject':    '[DIAG] URGENT: Verify account immediately — test',
        'body':       'Your account suspended. Click: http://verify-now.tk/login Enter SSN and PIN.',
        'user_email': 'test@diagnostic.internal',
    }
    test_email_id = store_email(email_data, None)
    check("store_email() inserts row", bool(test_email_id), f"email_id={test_email_id}")
except Exception as e:
    check("store_email", False, str(e))
    traceback.print_exc()

# Verify the row is actually in the DB
if test_email_id:
    try:
        row = fetch_one("SELECT id, sender, label FROM emails WHERE id = %s", (test_email_id,))
        check("Row readable from DB after insert", bool(row),
              f"label='{row['label']}'" if row else "not found")
    except Exception as e:
        check("Row read-back", False, str(e))

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 6: HYBRID ANALYSIS (full pipeline)
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 6: HYBRID ANALYSIS ENGINE':^70}")
print(sep)

label = confidence = None
try:
    from hybrid_analysis import hybrid_analyze_email
    check("hybrid_analyze_email import", True)
except Exception as e:
    check("hybrid_analyze_email import", False, str(e))

if test_email_id and model_loader:
    try:
        label, confidence = hybrid_analyze_email(
            test_email_id,
            email_data['body'],
            email_data['subject'],
            model_loader
        )
        check("hybrid_analyze_email() returns result", True,
              f"label={label.upper()}  confidence={confidence:.3f}")
        check("Phishing email detected (not safe)", label == 'phishing',
              f"Got: {label.upper()}")
    except Exception as e:
        check("hybrid_analyze_email()", False, str(e))
        traceback.print_exc()

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 7: RESULT WRITTEN BACK TO DATABASE
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 7: RESULT PERSISTENCE':^70}")
print(sep)

if test_email_id:
    try:
        result_row = fetch_one(
            "SELECT label, confidence_score, threat_explanation FROM emails WHERE id = %s",
            (test_email_id,)
        )
        if result_row:
            check("Label written to DB",           bool(result_row['label']),
                  f"label='{result_row['label']}'")
            check("Confidence written to DB",      result_row['confidence_score'] is not None,
                  f"score={result_row['confidence_score']}")
            check("Threat explanation written",    bool(result_row.get('threat_explanation')),
                  (result_row.get('threat_explanation') or '')[:60])
            check("DB label matches analysis",     result_row['label'] == label,
                  f"DB='{result_row['label']}' Analysis='{label}'")
        else:
            check("Result row found in DB", False, "row not found")
    except Exception as e:
        check("Result persistence check", False, str(e))

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 8: LOGS TABLE WRITTEN
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 8: AUDIT LOG WRITTEN':^70}")
print(sep)

if test_email_id:
    try:
        log_rows = fetch_all(
            "SELECT action, details FROM logs WHERE email_id = %s ORDER BY id DESC LIMIT 5",
            (test_email_id,)
        )
        check("Log entries exist for email", bool(log_rows),
              f"{len(log_rows)} log rows")
        for lr in log_rows:
            print(f"      action='{lr['action']}' | {(lr.get('details') or '')[:50]}")
    except Exception as e:
        check("Logs check", False, str(e))

# ──────────────────────────────────────────────────────────────────────────────
# STAGE 9: CIRCULAR IMPORT CHECK (mta_listener)
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{'STAGE 9: CIRCULAR IMPORT RISK (mta_listener)':^70}")
print(sep)

# mta_listener imports from app.py at runtime which is a circular import
# when the listener is triggered from within app.py itself.
import ast
mta_path = os.path.join(os.path.dirname(__file__), 'backend', 'ingestion', 'mta_listener.py')
try:
    with open(mta_path) as f:
        src = f.read()
    has_circular = 'from app import' in src or 'import app' in src
    check("mta_listener has NO circular 'from app import'", not has_circular,
          "⚠️  CIRCULAR IMPORT DETECTED — will crash when called from within Flask!" if has_circular else "Clean")
    if has_circular:
        print("      → Fix: pass analyze_email_content as a callback instead of importing app")
except Exception as e:
    check("mta_listener source check", False, str(e))

# ──────────────────────────────────────────────────────────────────────────────
# CLEANUP
# ──────────────────────────────────────────────────────────────────────────────
if test_email_id:
    try:
        execute_query("DELETE FROM logs WHERE email_id = %s", (test_email_id,))
        execute_query("DELETE FROM emails WHERE id = %s", (test_email_id,))
        print(f"\n  [Cleanup] Removed test email id={test_email_id} and its logs")
    except Exception as e:
        print(f"\n  [Cleanup error] {e}")

# ──────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print(f"  PIPELINE DIAGNOSTIC SUMMARY")
print(SEP)
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
total  = len(results)
print(f"  Passed: {passed}/{total}   Failed: {failed}/{total}\n")
for name, ok in results:
    print(f"  {'[OK]' if ok else '[X] '} {name}")
print(f"\n{SEP}")
if failed == 0:
    print("  [OK] ALL PIPELINE STAGES HEALTHY")
else:
    print(f"  [!]  {failed} ISSUE(S) NEED ATTENTION -- see [X] items above")
print(SEP)
