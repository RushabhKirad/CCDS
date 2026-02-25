import os
import joblib

# Paths to models (adjust relative paths as per your structure)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "..", "..", "models")

TEXT_MODEL_PATH = os.path.join(MODELS_DIR, "text_phishing_model.pkl")
TEXT_VECT_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")
ATT_MODEL_PATH = os.path.join(MODELS_DIR, "attachment_model.pkl")
URL_MODEL_PATH = os.path.join(MODELS_DIR, "url_model.pkl")
URL_VECT_PATH = os.path.join(MODELS_DIR, "url_vectorizer.pkl")

class ModelLoader:
    def __init__(self):
        # Load text model + vectorizer
        self.text_model = self._load_model(TEXT_MODEL_PATH)
        self.text_vect = self._load_model(TEXT_VECT_PATH)

        # Load attachment model
        self.attachment_model = self._load_model(ATT_MODEL_PATH)

        # Load URL model + vectorizer
        self.url_model = self._load_model(URL_MODEL_PATH)
        self.url_vect = self._load_model(URL_VECT_PATH)

    def _load_model(self, path):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {path}")
        return joblib.load(path)

# Usage Example:
# loader = ModelLoader()
# loader.text_model.predict(...)
# loader.attachment_model.predict(...)
