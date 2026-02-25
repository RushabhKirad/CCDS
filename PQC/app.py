from flask import Flask, render_template, request, jsonify
from crypto_utils import get_crypto_demo_data

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/simulate', methods=['POST'])
def simulate():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400
        
    demo_data = get_crypto_demo_data(username, password)
    return jsonify(demo_data)

if __name__ == '__main__':
    app.run(debug=True)
