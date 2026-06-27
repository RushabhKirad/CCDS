"""
verify_models.py
=================
Standalone verification script for the Email Security System.
Tests the domain credibility analyzer and the full model pipeline
WITHOUT needing a database connection.

Tests covered:
  1. Domain credibility scoring for known legitimate domains
  2. Domain credibility scoring for known phishing domains
  3. URL model — phishing vs safe URLs
  4. Text model — phishing vs safe text
  5. Attachment model — benign vs suspicious feature vectors
  6. End-to-end dampener simulation (false positive fix)
"""
import sys
import os
import re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = "  [OK]"
FAIL = "  [X] "
WARN = "  [!] "
SEP  = "=" * 70
sep  = "-" * 50

results = []

def check(label, ok, detail=""):
    sym = PASS if ok else FAIL
    msg = f"{sym} {label}" + (f" — {detail}" if detail else "")
    print(msg)
    results.append((label, ok))
    return ok

def section(title):
    print(f"\n{title:^70}")
    print(sep)

# ────────────────────────────────────────────────────────────────────────────
# SECTION 1: DOMAIN CREDIBILITY ANALYZER
# ────────────────────────────────────────────────────────────────────────────
section("SECTION 1: DOMAIN CREDIBILITY SCORES")

try:
    from backend.analyzers.domain_credibility import DomainCredibilityAnalyzer
    dca = DomainCredibilityAnalyzer()
    check("DomainCredibilityAnalyzer import", True)
except Exception as e:
    check("DomainCredibilityAnalyzer import", False, str(e))
    print(f"\n{SEP}\nCannot continue — domain_credibility.py failed to import.\n{SEP}")
    sys.exit(1)

# Legitimate domains — should score >= 0.50
LEGIT_DOMAINS = [
    ("naukri.com",        "Job portal",         0.50),
    ("internshala.com",   "Internship portal",  0.50),
    ("openai.com",        "AI company",         0.50),
    ("gmail.com",         "Email provider",     0.50),
    ("github.com",        "Dev platform",       0.50),
    ("linkedin.com",      "Professional net",   0.50),
    ("amazon.com",        "E-commerce",         0.50),
    ("microsoft.com",     "Tech company",       0.50),
    ("coursera.org",      "Education",          0.50),
    ("flipkart.com",      "E-commerce India",   0.50),
]

print("\n  [Legitimate Domains — expect credibility >= 0.50]")
for domain, desc, min_score in LEGIT_DOMAINS:
    try:
        score = dca.score(domain)
        detail_r = dca.get_detail(domain)
        ok = score >= min_score
        check(f"  {domain:<25} ({desc})", ok,
              f"score={score:.3f} {'PASS' if ok else f'FAIL — expected >={min_score}'}")
    except Exception as e:
        check(f"  {domain}", False, str(e))

# Phishing/suspicious domains — should score < 0.35
PHISH_DOMAINS = [
    ("paypal-verify.tk",       "Phishing TLD",      0.35),
    ("secure-login-account.ml","Phishing keywords", 0.35),
    ("google-security.cf",     "Brand abuse",       0.35),
    ("verify-account-now.xyz", "Phishing pattern",  0.35),
    ("bank-secure-login.pw",   "Suspicious",        0.35),
]

print("\n  [Phishing Domains — expect credibility < 0.35]")
for domain, desc, max_score in PHISH_DOMAINS:
    try:
        score = dca.score(domain)
        ok = score < max_score
        check(f"  {domain:<25} ({desc})", ok,
              f"score={score:.3f} {'PASS' if ok else f'FAIL — expected <{max_score}'}")
    except Exception as e:
        check(f"  {domain}", False, str(e))

# ────────────────────────────────────────────────────────────────────────────
# SECTION 2: MODEL LOADING
# ────────────────────────────────────────────────────────────────────────────
section("SECTION 2: MODEL LOADING")

model_loader = None
try:
    from backend.analyzers.model_loader import ModelLoader
    model_loader = ModelLoader()
    check("ModelLoader instantiation", True)
    check("text_model loaded",      hasattr(model_loader, 'text_model')      and model_loader.text_model      is not None, type(model_loader.text_model).__name__)
    check("text_vect loaded",       hasattr(model_loader, 'text_vect')       and model_loader.text_vect       is not None, type(model_loader.text_vect).__name__)
    check("url_model loaded",       hasattr(model_loader, 'url_model')       and model_loader.url_model       is not None, type(model_loader.url_model).__name__)
    check("url_vect loaded",        hasattr(model_loader, 'url_vect')        and model_loader.url_vect        is not None, type(model_loader.url_vect).__name__)
    check("attachment_model loaded",hasattr(model_loader, 'attachment_model') and model_loader.attachment_model is not None, type(model_loader.attachment_model).__name__)
except Exception as e:
    check("ModelLoader", False, str(e))
    model_loader = None

# ────────────────────────────────────────────────────────────────────────────
# SECTION 3: TEXT MODEL PREDICTIONS
# ────────────────────────────────────────────────────────────────────────────
section("SECTION 3: TEXT MODEL PREDICTIONS")

TEXT_TESTS = [
    # (text, expected_label, description)
    ("Your account has been suspended. Click here to verify immediately. Enter SSN and PIN.",
     "phishing", "Clear phishing text"),
    ("URGENT: Verify your account now! Click http://fake-verify.tk/login",
     "phishing", "Phishing with urgency"),
    ("Hi, just checking on the meeting tomorrow. See you at 10am.",
     "safe",     "Normal greeting"),
    ("Your order #12345 has been shipped. Expected delivery: Wednesday.",
     "safe",     "Order notification"),
]

if model_loader:
    for text, expected, desc in TEXT_TESTS:
        try:
            vec = model_loader.text_vect.transform([text])
            proba = model_loader.text_model.predict_proba(vec)[0]
            raw = proba[1] if len(proba) > 1 else proba[0]
            # Apply same noise-floor as hybrid_analysis.py
            effective = raw if raw >= 0.65 else raw * 0.5
            predicted = "phishing" if effective >= 0.5 else "safe"
            ok = predicted == expected
            check(f"  '{desc}'", ok,
                  f"Pred={predicted.upper()} Raw={raw:.3f} Eff={effective:.3f} Exp={expected.upper()}")
        except Exception as e:
            check(f"  Text pred '{desc}'", False, str(e))
else:
    print("  [SKIP] Model loader not available")

# ────────────────────────────────────────────────────────────────────────────
# SECTION 4: URL MODEL PREDICTIONS
# ────────────────────────────────────────────────────────────────────────────
section("SECTION 4: URL MODEL PREDICTIONS")

URL_TESTS = [
    ("http://paypal-verify.tk/login",          "phishing", "Known phishing URL"),
    ("http://bit.ly/3xScAmLink",               "phishing", "URL shortener"),
    ("http://192.168.1.1/admin/verify",        "phishing", "IP address URL"),
    ("http://google-security-check.xyz/verify","phishing", "Brand abuse + bad TLD"),
    ("https://www.google.com",                 "safe",     "Google"),
    ("https://www.naukri.com/jobs",            "safe",     "Naukri job listing"),
    ("https://openai.com/blog",                "safe",     "OpenAI blog"),
    ("https://github.com/user/repo",           "safe",     "GitHub repo"),
    ("https://www.internshala.com",            "safe",     "Internshala"),
    ("https://www.amazon.in/checkout",         "safe",     "Amazon India"),
]

if model_loader:
    passed = 0
    for url, expected, desc in URL_TESTS:
        try:
            vec = model_loader.url_vect.transform([url])
            proba = model_loader.url_model.predict_proba(vec)[0]
            score = proba[1] if len(proba) > 1 else proba[0]
            predicted = "phishing" if score >= 0.5 else "safe"
            ok = predicted == expected
            if ok:
                passed += 1
            check(f"  '{desc}'", ok,
                  f"Pred={predicted.upper()} Score={score:.3f} Exp={expected.upper()}")
        except Exception as e:
            check(f"  URL pred '{desc}'", False, str(e))
    print(f"\n  URL Model Accuracy: {passed}/{len(URL_TESTS)} = {100*passed/len(URL_TESTS):.0f}%")
else:
    print("  [SKIP] Model loader not available")

# ────────────────────────────────────────────────────────────────────────────
# SECTION 5: ATTACHMENT MODEL PREDICTIONS
# ────────────────────────────────────────────────────────────────────────────
section("SECTION 5: ATTACHMENT MODEL PREDICTIONS")

# Feature order: pdf_size, metadata_size, pages, xref_length, title_characters,
#   isEncrypted, embedded_files, images, contains_text, JS, Javascript,
#   AA, OpenAction, Acroform, JBIG2Decode, RichMedia, launch,
#   EmbeddedFile, XFA, URI, Colors
ATTACHMENT_TESTS = [
    # (features_dict, expected_label, description)
    # Feature order matches FEATURES list in attachment_analyzer.py:
    # pdf_size, metadata_size, pages, xref_length, title_characters,
    # isEncrypted, embedded_files, images, contains_text, JS, Javascript,
    # AA, OpenAction, Acroform, JBIG2Decode, RichMedia, launch,
    # EmbeddedFile, XFA, URI, Colors
    ([50000, 200, 5, 10, 20, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
     "safe",     "Normal PDF with text and images, no JS"),
    ([120000, 0, 1, 50, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0],
     "phishing", "Malicious PDF with JS, AA, OpenAction, Launch"),
]

if model_loader:
    import pandas as pd
    # Full 31-feature list matching retrained model
    FEATURE_NAMES = [
        'pdf_size', 'metadata_size', 'pages', 'xref_length', 'title_characters',
        'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref',
        'pageno', 'encrypt', 'ObjStm',
        'isEncrypted', 'embedded_files', 'images', 'contains_text',
        'JS', 'Javascript', 'AA', 'OpenAction', 'Acroform',
        'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA', 'URI', 'Colors'
    ]
    # Values: pdf_size(KB), meta, pages, xref_len, title_chars,
    #         obj, endobj, stream, endstream, xref, trailer, startxref,
    #         pageno, encrypt, ObjStm,
    #         isEncrypted, embedded_files, images, contains_text,
    #         JS, Javascript, AA, OpenAction, Acroform,
    #         JBIG2Decode, RichMedia, launch, EmbeddedFile, XFA, URI, Colors
    ATTACHMENT_TESTS = [
        ([50, 200, 5, 10, 20, 25, 25, 5, 5, 1, 1, 1, 5, 0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
         "safe",     "Normal PDF — typical benign document"),
        ([8, 180, 1, 5, 0, 10, 10, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0],
         "phishing", "Malicious PDF — JS, OpenAction, AA, Launch"),
    ]
    for features, expected, desc in ATTACHMENT_TESTS:
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                df_feat = pd.DataFrame([features], columns=FEATURE_NAMES)
                proba = model_loader.attachment_model.predict_proba(df_feat)[0]
            score = proba[1] if len(proba) > 1 else proba[0]
            predicted = "phishing" if score >= 0.5 else "safe"
            ok = predicted == expected
            check(f"  '{desc}'", ok,
                  f"Pred={predicted.upper()} Score={score:.3f} Exp={expected.upper()}")
        except Exception as e:
            check(f"  Attachment pred '{desc}'", False, str(e))
else:
    print("  [SKIP] Model loader not available")


# ────────────────────────────────────────────────────────────────────────────
# SECTION 6: END-TO-END DAMPENER SIMULATION (False Positive Fix)
# ────────────────────────────────────────────────────────────────────────────
section("SECTION 6: DAMPENER SIMULATION (False Positive Fix)")
print("  Simulates what the ensemble does for legitimate domain emails")
print("  that contain marketing/notification language the ML scores high.")

if model_loader:
    # Test emails that were previously false positives
    FP_TESTS = [
        {
            "sender": "noreply@naukri.com",
            "subject": "New job opportunities matching your profile",
            "body": "We found 5 new jobs matching your profile. Click to view and apply now. Your account shows high match.",
            "domain": "naukri.com",
            "expected": "safe",
            "desc": "Naukri job alert (was false positive)",
        },
        {
            "sender": "noreply@openai.com",
            "subject": "Verify your OpenAI account",
            "body": "Please verify your account to continue using OpenAI services. Click the link below to confirm your email.",
            "domain": "openai.com",
            "expected": "safe",
            "desc": "OpenAI verification email (was false positive)",
        },
        {
            "sender": "alerts@internshala.com",
            "subject": "URGENT: 2 internships closing today — Apply now",
            "body": "Internships closing today. Update your profile and apply now. Don't miss out on these opportunities.",
            "domain": "internshala.com",
            "expected": "safe",
            "desc": "Internshala urgency alert (was false positive)",
        },
        {
            "sender": "attacker@paypal-verify.tk",
            "subject": "URGENT: Verify account immediately",
            "body": "Your account suspended click here verify account SSN PIN bank account immediately 24 hours.",
            "domain": "paypal-verify.tk",
            "expected": "phishing",
            "desc": "Clear phishing from bad domain (must still be caught)",
        },
    ]

    for t in FP_TESTS:
        try:
            # 1. Get text ML score
            text_content = t['body'] + " " + t['subject']
            vec = model_loader.text_vect.transform([text_content])
            proba = model_loader.text_model.predict_proba(vec)[0]
            raw_ml = proba[1] if len(proba) > 1 else proba[0]
            text_ml_score = raw_ml if raw_ml >= 0.65 else raw_ml * 0.5

            # 2. Rule score
            high_risk_patterns = [
                r'(verify|confirm|update).*(account|password|payment)',
                r'(suspended|locked|blocked).*(account|access)',
                r'(ssn|social security|pin|cvv|credit card)',
                r'(bank account|routing number|wire transfer)',
            ]
            text_rule_score = 0
            for pat in high_risk_patterns:
                if re.search(pat, text_content.lower()):
                    text_rule_score += 0.20
            text_rule_score = min(1.0, text_rule_score)

            # 3. Text combined
            text_final = (text_ml_score * 0.6) + (text_rule_score * 0.4)

            # 4. Ensemble (no URLs, no attachment)
            ensemble = text_final * 0.80

            # 5. Domain credibility
            credibility = dca.score(t['domain'])

            # 6. Apply dampener (no hard rule signals when rule_score < 0.20)
            has_hard = text_rule_score > 0.20
            if credibility >= 0.50 and not has_hard:
                dampener = 1.0 - (credibility * 0.55)
                ensemble_after = ensemble * dampener
            else:
                dampener = 1.0
                ensemble_after = ensemble

            # 7. High-credibility safety net
            if credibility >= 0.70 and 0.30 <= ensemble_after < 0.50 and not has_hard:
                ensemble_after *= 0.65

            # 8. False positive guard
            if 0.35 <= ensemble_after < 0.68 and text_rule_score <= 0.05:
                ensemble_after = 0.30

            predicted = "phishing" if ensemble_after >= 0.35 else "safe"
            ok = predicted == t['expected']

            check(f"  {t['desc']}", ok,
                  f"ML={raw_ml:.2f} Rules={text_rule_score:.2f} Cred={credibility:.2f} "
                  f"Ens={ensemble:.2f}->{ensemble_after:.2f} Pred={predicted.upper()}")
        except Exception as e:
            check(f"  {t['desc']}", False, str(e))
else:
    print("  [SKIP] Model loader not available")

# ────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ────────────────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
print("  VERIFICATION SUMMARY")
print(SEP)
passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
total  = len(results)
print(f"  Passed: {passed}/{total}   Failed: {failed}/{total}\n")
for name, ok in results:
    print(f"  {'[OK]' if ok else '[X] '} {name}")
print(f"\n{SEP}")
if failed == 0:
    print("  [OK] ALL CHECKS PASSED — System ready for deployment")
else:
    print(f"  [!]  {failed} CHECK(S) FAILED — Review [X] items above")
print(SEP)
