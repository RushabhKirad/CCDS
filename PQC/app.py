from flask import Flask, render_template, request, jsonify
from crypto_utils import get_crypto_demo_data, get_benchmark_data

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

@app.route('/benchmark', methods=['POST'])
def benchmark():
    """
    Run live benchmarks and return structured metrics for:
      - Key-exchange latency (ms)
      - Scalability (ops/sec, sessions/min)
      - Computational overhead (memory KB, key/CT sizes)
    Optional JSON body: { "iterations": N }  (default 50)
    """
    body       = request.get_json(silent=True) or {}
    iterations = int(body.get("iterations", 50))
    iterations = max(10, min(iterations, 500))   # clamp 10..500

    data = get_benchmark_data(iterations)
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
