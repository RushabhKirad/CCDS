import joblib
import os
from pathlib import Path

try:
    path = Path("data/models/advanced_model_metadata.joblib")
    if not path.exists():
        print("Error: Metadata file not found at", path)
        exit(1)

    metadata = joblib.load(path)
    
    print("\n--- 🧠 Model Performance Metrics ---")
    print(f"Ensemble AUC Score: {metadata.get('ensemble_auc', 'N/A'):.4f}")
    
    ind_aucs = metadata.get('individual_aucs', {})
    print("\n--- Individual Model Contributions ---")
    for name, score in ind_aucs.items():
        print(f"{name.upper()}: {score:.4f}")

except Exception as e:
    print(f"Error reading metadata: {e}")
