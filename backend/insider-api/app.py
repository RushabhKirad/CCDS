from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import datetime

app = Flask(__name__)
CORS(app)

try:
    from core.database import DatabaseManager
    from core.threat_detector import ThreatDetector
    db = DatabaseManager()
    threat_detector = ThreatDetector()
    print("Insider threat detection initialized")
except Exception as e:
    print(f"Initialization error: {e}")
    db = None
    threat_detector = None

@app.route("/api/health")
def health():
    return jsonify({
        'status': 'healthy',
        'service': 'insider-threat-detection',
        'database': db is not None,
        'threat_detector': threat_detector is not None
    })

@app.route("/api/alerts")
def get_alerts():
    try:
        if db:
            alerts = db.get_recent_alerts(20)
            return jsonify({'alerts': alerts})
        return jsonify({'alerts': []})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/test_alert", methods=["POST"])
def test_alert():
    try:
        if threat_detector:
            threat_detector.handle_usb_connection('E:\\')
            return jsonify({'message': 'Test alert created'})
        return jsonify({'error': 'Threat detector not available'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5002)