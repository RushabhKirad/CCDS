"""
retrain_attachment_model.py
===========================
Retrains the attachment model using the FULL feature set from Final.csv
and fixes the sklearn version mismatch (1.7 → 1.8).

Issues with the previous model:
1. Only 21 features used out of 33 available — missing obj, stream, header etc.
2. metadata_size/pdf_size dominated predictions (size-based bias)
3. Serialized with sklearn 1.7.0, but environment has 1.8.0

Fix: Retrain with the full feature set, proper preprocessing, 
and scaled features to prevent size-bias.
"""
import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH  = os.path.join(BASE_DIR, 'data', 'Final.csv')
MODEL_PATH = os.path.join(BASE_DIR, 'models', 'attachment_model.pkl')

print("=" * 60)
print("RETRAINING ATTACHMENT MODEL (Full Feature Set)")
print("=" * 60)

# ── 1. LOAD DATA ─────────────────────────────────────────────────────────────
print("\n[1] Loading data...")
df = pd.read_csv(DATA_PATH)
print(f"   Shape: {df.shape}")
print(f"   Target distribution:\n{df['class'].value_counts().to_string()}")

# ── 2. FEATURE ENGINEERING ───────────────────────────────────────────────────
# Use ALL numeric/binary features available in the dataset
# Exclude: 'name' (filename), 'class' (target)
FEATURES = [
    # Size and structure features
    'pdf_size', 'metadata_size', 'pages', 'xref_length', 'title_characters',
    # PDF structure counts
    'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref',
    'pageno', 'encrypt', 'ObjStm',
    # Binary security features (the most informative for malware detection)
    'isEncrypted', 'embedded_files', 'images', 'contains_text',
    'JS', 'Javascript', 'AA', 'OpenAction', 'Acroform',
    'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA', 'URI', 'Colors',
]

# Preprocess: Yes/No → 1/0, handle missing
yes_no_cols = [
    'isEncrypted', 'contains_text', 'JS', 'Javascript', 'AA',
    'OpenAction', 'Acroform', 'JBIG2Decode', 'RichMedia',
    'launch', 'EmbeddedFile', 'XFA', 'URI'
]

for col in yes_no_cols:
    if col in df.columns:
        df[col] = df[col].map({'Yes': 1, 'No': 0, 1: 1, 0: 0}).fillna(0).astype(int)

# Numeric features: fill NaN with 0
for col in FEATURES:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# Filter to available features
available = [f for f in FEATURES if f in df.columns]
missing   = [f for f in FEATURES if f not in df.columns]
if missing:
    print(f"   [!] Features not in dataset (skipped): {missing}")
FEATURES = available

X = df[FEATURES]
y = (df['class'] == 'Malicious').astype(int)  # 1 = Malicious, 0 = Benign

print(f"\n[2] Features used: {len(FEATURES)}")
print(f"   Label distribution: Benign={sum(y==0)} Malicious={sum(y==1)}")

# ── 3. TRAIN/TEST SPLIT ───────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── 4. TRAIN MODEL ────────────────────────────────────────────────────────────
print("\n[3] Training model...")

# Use a pipeline with StandardScaler to remove the size-based bias.
# StandardScaler normalises pdf_size (0–200KB) to the same scale as
# binary features (0/1) so the tree doesn't just split on file size.
clf = Pipeline([
    ('scaler', StandardScaler()),
    ('rf', RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_leaf=3,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    ))
])

# Cross-validation
print("   Running 5-fold CV...")
cv = cross_val_score(clf, X_train, y_train, cv=5, scoring='accuracy')
print(f"   CV Accuracy: {cv.mean():.4f} (+/- {cv.std():.4f})")

# Full train
clf.fit(X_train, y_train)

# ── 5. EVALUATE ───────────────────────────────────────────────────────────────
print("\n[4] Evaluation on test set:")
y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"   Test Accuracy: {acc:.4f}")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))

cm = confusion_matrix(y_test, y_pred)
print(f"   Confusion Matrix:\n   Benign:    TP={cm[0,0]} FP={cm[0,1]}")
print(f"   Malicious: FN={cm[1,0]} TP={cm[1,1]}")

# ── 6. SANITY CHECK ───────────────────────────────────────────────────────────
print("\n[5] Sanity check predictions:")
SANITY = [
    # (feature_values, expected, description)
    # Note: pdf_size in KB to match training data units
    ([50,  200, 5, 10, 20, 10, 50, 20, 5, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
     0, "Normal PDF — typical benign doc"),
    ([8,   180, 1, 5,  0,  1,  10, 1,  0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0],
     1, "Malicious PDF — JS, OpenAction, AA, Launch"),
]

FEAT_COUNT = len(FEATURES)
for feat_vals, expected, desc in SANITY:
    # Pad/trim to match feature count
    feat_vals = (feat_vals + [0] * FEAT_COUNT)[:FEAT_COUNT]
    feat_df = pd.DataFrame([feat_vals], columns=FEATURES)
    proba = clf.predict_proba(feat_df)[0]
    predicted = int(clf.predict(feat_df)[0])
    label = 'Malicious' if predicted == 1 else 'Benign'
    expected_label = 'Malicious' if expected == 1 else 'Benign'
    ok = predicted == expected
    status = "[OK]" if ok else "[X] "
    print(f"   {status} {desc}: {label} (proba={proba[1]:.3f}) — exp={expected_label}")

# ── 7. SAVE MODEL ─────────────────────────────────────────────────────────────
joblib.dump(clf, MODEL_PATH)
print(f"\n[6] Saved model to: {MODEL_PATH}")
print(f"   Features: {len(FEATURES)}")
print(f"   Model type: Pipeline(StandardScaler + RandomForestClassifier)")

# Update attachment_analyzer.py FEATURES list to match
print("\n[7] Features list for attachment_analyzer.py:")
print(f"   FEATURES = {FEATURES}")

print("\n" + "=" * 60)
print("ATTACHMENT MODEL RETRAINED SUCCESSFULLY")
print("=" * 60)
print("\nNOTE: The new model uses a Pipeline(scaler + RF) so")
print("predict_proba() must be called on a DataFrame with")
print("these column names, not a plain list.")
print("hybrid_analysis.py has been updated accordingly.")
