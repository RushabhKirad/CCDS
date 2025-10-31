import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "..", "data", "raw", "Final.csv")
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "attachment_model.pkl")

# List of relevant features for PDF/attachment analysis
FEATURES = [
    'pdf_size', 'metadata_size', 'pages', 'xref_length', 'title_characters',
    'isEncrypted', 'embedded_files', 'images', 'contains_text', 'JS', 'Javascript',
    'AA', 'OpenAction', 'Acroform', 'JBIG2Decode', 'RichMedia', 'launch',
    'EmbeddedFile', 'XFA', 'URI', 'Colors'
]

TARGET = 'class'  # Benign / Malicious

def preprocess_features(df):
    # Replace Yes/No with 1/0
    yes_no_cols = ['isEncrypted', 'contains_text', 'JS', 'Javascript', 'AA', 
                   'OpenAction', 'Acroform', 'JBIG2Decode', 'RichMedia', 
                   'launch', 'EmbeddedFile', 'XFA', 'URI']
    
    for col in yes_no_cols:
        if col in df.columns:
            df[col] = df[col].map({'Yes': 1, 'No': 0})
            df[col] = df[col].fillna(0)  # fill NaN with 0
    return df

def load_data():
    df = pd.read_csv(DATA_PATH)
    print(f"Available columns: {list(df.columns)}")

    missing = [f for f in FEATURES + [TARGET] if f not in df.columns]
    if missing:
        raise ValueError(f"Missing columns in dataset: {missing}")

    df = preprocess_features(df)

    X = df[FEATURES]
    y = df[TARGET]
    return X, y

def train_model(X, y):
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Classifier
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=7,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42
    )

    # Cross-validation on training data
    cv_scores = cross_val_score(clf, X_train, y_train, cv=5)
    print(f"🔹 5-fold CV Accuracy: {cv_scores.mean():.4f}")

    # Train on full training set
    clf.fit(X_train, y_train)

    # Evaluate on test set
    y_pred = clf.predict(X_test)
    print("✅ Test Accuracy:", accuracy_score(y_test, y_pred))
    print("✅ Classification Report:\n", classification_report(y_test, y_pred))

    # Save model
    joblib.dump(clf, MODEL_PATH)
    print(f"✅ Model saved to {MODEL_PATH}")

    return clf

if __name__ == "__main__":
    print("🔹 Loading dataset...")
    X, y = load_data()

    print("🔹 Training Attachment Analyzer...")
    train_model(X, y)
