from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import datetime

app = Flask(__name__)
CORS(app)

try:
    from analyzers.model_loader import ModelLoader
    model_loader = ModelLoader()
    print("ML models loaded")
except Exception as e:
    print(f"Model loading error: {e}")
    model_loader = None

try:
    from crypto.pqc_handler import pqc_handler
    print("PQC initialized")
except Exception as e:
    print(f"PQC error: {e}")
    pqc_handler = None

@app.route("/api/health")
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'phishing-detection',
        'ml_models': model_loader is not None,
        'pqc_enabled': pqc_handler is not None
    })

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()
        email_text = data.get('email_text', '')
        subject = data.get('subject', '')
        
        from hybrid_analysis import hybrid_analyze_email
        label, confidence = hybrid_analyze_email(0, email_text, subject, model_loader)
        
        return jsonify({
            'prediction': label,
            'confidence': confidence,
            'threat_level': 'high' if label == 'phishing' and confidence > 0.8 else 'low'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5001)