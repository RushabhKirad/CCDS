import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, accuracy_score

# Paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
DATA_PATH = os.path.join(PROJECT_ROOT, "data", "raw", "processed_emails.csv")
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "text_phishing_model.pkl")
VECTORIZER_PATH = os.path.join(PROJECT_ROOT, "models", "vectorizer.pkl")

def train_text_analyzer():
    # Load dataset
    df = pd.read_csv(DATA_PATH)

    # Assume dataset has 'text' and 'label' columns
    X = df["text"].astype(str)
    y = df["label"]

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # TF-IDF vectorizer
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    # Classifier
    clf = LogisticRegression(max_iter=500, class_weight="balanced")
    clf.fit(X_train_tfidf, y_train)

    # Evaluation
    y_pred = clf.predict(X_test_tfidf)
    print("✅ Accuracy:", accuracy_score(y_test, y_pred))
    print("✅ Report:\n", classification_report(y_test, y_pred))

    # Save model + vectorizer
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"✅ Model saved to {MODEL_PATH}")
    print(f"✅ Vectorizer saved to {VECTORIZER_PATH}")

def predict_text(sample_text: str):
    clf = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)

    X = vectorizer.transform([sample_text])
    prediction = clf.predict(X)[0]
    return prediction

if __name__ == "__main__":
    # Train once
    train_text_analyzer()

    # Test quick prediction
    test_mail = "Your account is locked, click here to reset password."
    print("Prediction:", predict_text(test_mail))
