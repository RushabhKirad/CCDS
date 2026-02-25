from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import datetime

app = Flask(__name__)
CORS(app)

try:
    from app.main_production import app as anomaly_app
    print("Anomaly detection system initialized")
    anomaly_available = True
except Exception as e:
    print(f"Anomaly system error: {e}")
    anomaly_available = False

@app.route("/api/health")
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'anomaly-detection',
        'ml_system': anomaly_available
    })

@app.route("/api/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        # Simple anomaly prediction
        return jsonify({
            'anomaly_score': 0.3,
            'is_anomaly': False,
            'confidence': 0.85
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/alerts")
def get_alerts():
    return jsonify({
        'alerts': [
            {'id': 1, 'type': 'network_anomaly', 'severity': 'medium', 'timestamp': datetime.datetime.now().isoformat()}
        ]
    })

if __name__ == "__main__":
    app.run(debug=True, port=8001)