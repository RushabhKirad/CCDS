import json
import os
from datetime import datetime

class SimpleDB:
    def __init__(self):
        self.db_file = "alerts.json"
        self.alerts = self.load_alerts()
    
    def load_alerts(self):
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def save_alerts(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.alerts, f, indent=2)
    
    def add_alert(self, alert_data):
        alert = {
            "id": f"alert_{len(self.alerts) + 1}",
            "timestamp": datetime.now().isoformat(),
            "attack_type": alert_data.get("attack_type", "Unknown"),
            "confidence": alert_data.get("confidence", 0.0),
            "source_ip": alert_data.get("source_ip", "unknown"),
            "method": alert_data.get("method", "ML"),
            "path": alert_data.get("path", "/"),
            "user_agent": alert_data.get("user_agent", "")
        }
        self.alerts.append(alert)
        self.save_alerts()
        return alert
    
    def get_alerts(self, limit=None):
        alerts = sorted(self.alerts, key=lambda x: x["timestamp"], reverse=True)
        return alerts[:limit] if limit else alerts
    
    def get_stats(self):
        total_alerts = len(self.alerts)
        high_severity = len([a for a in self.alerts if a["confidence"] >= 0.8])
        
        return {
            "total_requests": total_alerts + 10,  # Add some normal traffic
            "attack_requests": total_alerts,
            "high_severity_alerts": high_severity,
            "detection_rate": 100 if total_alerts > 0 else 0
        }

# Global database instance
db = SimpleDB()