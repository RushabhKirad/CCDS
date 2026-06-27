import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Paths — go up three levels from backend/analyzers/ to project root
ROOT_DIR        = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_PATH       = os.path.join(ROOT_DIR, 'data', 'Final.csv')
MODEL_PATH      = os.path.join(ROOT_DIR, 'models', 'url_model.pkl')
VECTORIZER_PATH = os.path.join(ROOT_DIR, 'models', 'url_vectorizer.pkl')

def load_data():
    df = pd.read_csv(DATA_PATH)
    print(f"Available columns: {list(df.columns)}")
    if "name" not in df.columns or "class" not in df.columns:
        raise ValueError("Dataset must have 'name' and 'class' columns")
    return df["name"].astype(str), df["class"]

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Vectorize URLs
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3,5), max_features=2000)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Random Forest classifier
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=5,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42
    )

    # 5-fold cross-validation
    cv_scores = cross_val_score(clf, X_train_vec, y_train, cv=5)
    print(f"🔹 5-fold CV Accuracy: {cv_scores.mean():.4f}")

    # Train on full training set
    clf.fit(X_train_vec, y_train)

    # Evaluate on test set
    y_pred = clf.predict(X_test_vec)
    print("✅ Test Accuracy:", accuracy_score(y_test, y_pred))
    print("✅ Classification Report:\n", classification_report(y_test, y_pred))

    # Save model + vectorizer
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"✅ Model saved to {MODEL_PATH}")
    print(f"✅ Vectorizer saved to {VECTORIZER_PATH}")

    return clf, vectorizer

if __name__ == "__main__":
    print("🔹 Loading dataset...")
    X, y = load_data()

    print("🔹 Training URL Analyzer...")
    train_model(X, y)
