import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Paths — BASE_DIR resolves to backend/analyzers, so go up two levels to project root
ROOT_DIR   = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_PATH  = os.path.join(ROOT_DIR, 'data', 'Final.csv')
MODEL_PATH = os.path.join(ROOT_DIR, 'models', 'attachment_model.pkl')

# Full feature list matching the retrained model (31 features)
FEATURES = [
    # Size and structural metadata
    'pdf_size', 'metadata_size', 'pages', 'xref_length', 'title_characters',
    # PDF structure object counts (raw numeric, extracted from PDF body)
    'obj', 'endobj', 'stream', 'endstream', 'xref', 'trailer', 'startxref',
    'pageno', 'encrypt', 'ObjStm',
    # Binary security features
    'isEncrypted', 'embedded_files', 'images', 'contains_text',
    'JS', 'Javascript', 'AA', 'OpenAction', 'Acroform',
    'JBIG2Decode', 'RichMedia', 'launch', 'EmbeddedFile', 'XFA', 'URI', 'Colors',
]

TARGET = 'class'  # Benign / Malicious

def extract_features(file_path):
    """Extracts features from a PDF file for the model."""
    import PyPDF2
    import re
    
    features = {k: 0 for k in FEATURES}
    
    try:
        if not os.path.exists(file_path):
            return list(features.values())
            
        file_size = os.path.getsize(file_path)
        features['pdf_size'] = file_size
        
        with open(file_path, 'rb') as f:
            try:
                pdf = PyPDF2.PdfReader(f)
                features['pages'] = len(pdf.pages)
                features['isEncrypted'] = 1 if pdf.is_encrypted else 0
                
                # Metadata analysis
                if pdf.metadata:
                    features['metadata_size'] = len(str(pdf.metadata))
                    if pdf.metadata.title:
                        features['title_characters'] = len(pdf.metadata.title)
                
                # Content analysis (simplified for speed)
                content = ""
                for page in pdf.pages[:5]: # Check first 5 pages
                    try:
                        text = page.extract_text()
                        if text:
                            features['contains_text'] = 1
                            content += text
                    except:
                        pass
                
                # Keyword search in raw content (better done on raw bytes but using text for now)
                # For deeper analysis we would scan raw bytes for PDF objects
                # Here we simulate detection of common malicious keywords in PDF structure
                # In a real scenario, we'd parse the PDF structure for /JS, /OpenAction etc.
                
                # Reading raw bytes for keyword search
                f.seek(0)
                raw_content = f.read()
                
                keywords = {
                    'JS': b'/JS', 'Javascript': b'/JavaScript', 'AA': b'/AA', 
                    'OpenAction': b'/OpenAction', 'Acroform': b'/AcroForm', 
                    'JBIG2Decode': b'/JBIG2Decode', 'RichMedia': b'/RichMedia', 
                    'launch': b'/Launch', 'EmbeddedFile': b'/EmbeddedFile', 
                    'XFA': b'/XFA', 'URI': b'/URI', 'Colors': b'/Colors'
                }
                
                for key, pattern in keywords.items():
                    if pattern in raw_content:
                        features[key] = 1
                        
            except Exception as e:
                print(f"PDF parsing error: {e}")
                
    except Exception as e:
        print(f"Feature extraction error: {e}")
        
    return list(features.values())

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
