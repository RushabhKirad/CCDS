#!/usr/bin/env python3
"""
Dashboard Server - Serves the live dashboard on local server
"""
from flask import Flask, render_template_string, send_from_directory
import os

app = Flask(__name__)

@app.route('/')
def dashboard():
    """Serve the live dashboard"""
    dashboard_path = os.path.join(os.path.dirname(__file__), 'live_dashboard.html')
    with open(dashboard_path, 'r', encoding='utf-8') as f:
        content = f.read()
    return render_template_string(content)

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

if __name__ == '__main__':
    print("🌐 Starting Dashboard Server...")
    print("📊 Dashboard available at: http://localhost:8002")
    app.run(host='127.0.0.1', port=8002, debug=False)