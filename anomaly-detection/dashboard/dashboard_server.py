#!/usr/bin/env python3
"""
Dashboard Server - Serves the live dashboard on local server
"""
from flask import Flask, render_template_string, send_from_directory, make_response
import os

app = Flask(__name__)

@app.route('/')
def dashboard():
    """Serve the live dashboard"""
    dashboard_path = os.path.join(os.path.dirname(__file__), 'live_dashboard_fixed.html')
    with open(dashboard_path, 'r', encoding='utf-8') as f:
        content = f.read()
    response = make_response(render_template_string(content))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

if __name__ == '__main__':
    print("🌐 Starting Dashboard Server...")
    print("📊 Dashboard available at: http://localhost:3030")
    app.run(host='127.0.0.1', port=3030, debug=False)