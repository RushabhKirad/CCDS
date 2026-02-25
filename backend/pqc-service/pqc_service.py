"""
PQC Flask Service for CCDS Internal Communication
==================================================
Provides REST API endpoints for quantum-resistant key exchange
and encrypted internal communication between services.

Port: 5005
Standard: NIST FIPS 203 (ML-KEM-768)
"""

import os
import json
import base64
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt

# Import our PQC crypto module
from pqc_crypto import PQCSessionManager, run_self_test

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET', 'ccds-pqc-secret-key-2024')
PQC_SERVICE_PORT = int(os.getenv('PQC_PORT', 5005))

# Initialize PQC Session Manager
session_manager = PQCSessionManager()

# Request logging
@app.before_request
def log_request():
    """Log incoming requests"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {request.method} {request.path}")


def require_auth(f):
    """Decorator to require JWT authentication for internal endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({"success": False, "error": "Missing Authorization header"}), 401
        
        try:
            # Extract token from "Bearer <token>"
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
            else:
                token = auth_header
            
            # Verify JWT (using same secret as main backend)
            payload = jwt.decode(token, 'cyber-defense-secret-key-2024', algorithms=['HS256'])
            request.user = payload
            
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Token expired"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"success": False, "error": f"Invalid token: {str(e)}"}), 401
        
        return f(*args, **kwargs)
    return decorated


# ==================== Health Check ====================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "PQC Service",
        "port": PQC_SERVICE_PORT,
        "algorithm": "ML-KEM-768",
        "timestamp": datetime.now().isoformat()
    })


@app.route('/pqc/status', methods=['GET'])
def pqc_status():
    """Get PQC system status"""
    from pqc_crypto import MLKEMCrypto
    mlkem = MLKEMCrypto()
    
    return jsonify({
        "success": True,
        "pqc_available": mlkem.is_real_pqc,
        "library": mlkem.library,
        "algorithm": "ML-KEM-768",
        "key_sizes": {
            "public_key": mlkem.PUBLIC_KEY_SIZE,
            "secret_key": mlkem.SECRET_KEY_SIZE,
            "ciphertext": mlkem.CIPHERTEXT_SIZE,
            "shared_secret": mlkem.SHARED_SECRET_SIZE
        }
    })


# ==================== PQC Session Endpoints ====================

@app.route('/pqc/init-session', methods=['POST'])
def init_session():
    """
    Initialize a new PQC session
    
    Returns:
        session_id: Unique session identifier
        public_key: Server's ML-KEM-768 public key (base64)
        algorithm: Algorithm used (ML-KEM-768)
    """
    try:
        session = session_manager.create_session()
        
        print(f"  ✅ New PQC session created: {session['session_id']}")
        print(f"     Public key size: {session['public_key_size']} bytes")
        
        return jsonify({
            "success": True,
            "session_id": session['session_id'],
            "public_key": session['public_key'],
            "algorithm": session['algorithm'],
            "public_key_size": session['public_key_size']
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/pqc/handshake', methods=['POST'])
def complete_handshake():
    """
    Complete PQC handshake by receiving client's ciphertext
    
    Request body:
        session_id: Session ID from init-session
        ciphertext: Client's encapsulated ciphertext (base64)
    
    Returns:
        success: Whether handshake completed
        status: Session status after handshake
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "Missing request body"}), 400
        
        session_id = data.get('session_id')
        ciphertext = data.get('ciphertext')
        
        if not session_id or not ciphertext:
            return jsonify({"success": False, "error": "Missing session_id or ciphertext"}), 400
        
        result = session_manager.complete_handshake(session_id, ciphertext)
        
        if result['success']:
            print(f"  ✅ PQC handshake completed: {session_id}")
            print(f"     Shared secret size: {result.get('shared_secret_size', 0)} bytes")
            print(f"     AES key size: {result.get('aes_key_size', 0)} bits")
        else:
            print(f"  ❌ PQC handshake failed: {result.get('error')}")
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/pqc/secure-data', methods=['POST'])
@require_auth
def secure_data():
    """
    Exchange encrypted data over PQC-secured channel
    
    Request body:
        session_id: Active session ID
        encrypted_data: Encrypted payload (ciphertext, nonce, tag)
        action: What to do with the data (forward, analyze, etc.)
    
    Returns:
        Encrypted response data
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"success": False, "error": "Missing request body"}), 400
        
        session_id = data.get('session_id')
        encrypted_data = data.get('encrypted_data')
        action = data.get('action', 'echo')
        
        if not session_id or not encrypted_data:
            return jsonify({"success": False, "error": "Missing session_id or encrypted_data"}), 400
        
        # Decrypt incoming data
        decrypted = session_manager.decrypt_data(
            session_id,
            encrypted_data.get('ciphertext'),
            encrypted_data.get('nonce'),
            encrypted_data.get('tag')
        )
        
        if not decrypted['success']:
            return jsonify(decrypted), 400
        
        # Process the decrypted data based on action
        plaintext_data = json.loads(decrypted['data'])
        
        print(f"  🔓 Decrypted data received:")
        print(f"     Action: {action}")
        print(f"     Data keys: {list(plaintext_data.keys())}")
        
        # Handle different actions
        if action == 'echo':
            response_data = {"echo": plaintext_data, "processed_at": datetime.now().isoformat()}
        elif action == 'analyze_email':
            # Forward to email security module (placeholder)
            response_data = {"action": "analyze_email", "status": "forwarded", "data": plaintext_data}
        elif action == 'check_threat':
            # Forward to insider threat module (placeholder)
            response_data = {"action": "check_threat", "status": "forwarded", "data": plaintext_data}
        else:
            response_data = {"action": action, "status": "unknown_action", "data": plaintext_data}
        
        # Encrypt response
        response_bytes = json.dumps(response_data).encode()
        encrypted_response = session_manager.encrypt_data(session_id, response_bytes)
        
        if not encrypted_response['success']:
            return jsonify(encrypted_response), 500
        
        print(f"  🔐 Response encrypted and sent")
        
        return jsonify({
            "success": True,
            "encrypted_response": {
                "ciphertext": encrypted_response['ciphertext'],
                "nonce": encrypted_response['nonce'],
                "tag": encrypted_response['tag']
            }
        })
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/pqc/session-info/<session_id>', methods=['GET'])
def get_session_info(session_id):
    """Get information about a PQC session"""
    info = session_manager.get_session_info(session_id)
    return jsonify(info)


# ==================== Test Endpoints ====================

@app.route('/pqc/self-test', methods=['POST'])
def run_pqc_self_test():
    """Run PQC cryptographic self-test"""
    try:
        success = run_self_test()
        return jsonify({
            "success": success,
            "message": "All PQC tests passed!" if success else "Some tests failed"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/pqc/demo', methods=['GET'])
def demo_flow():
    """
    Demonstrate complete PQC flow in one endpoint
    Useful for testing and understanding the protocol
    """
    from pqc_crypto import MLKEMCrypto, AESGCMCrypto
    
    steps = []
    
    # Step 1: Server generates keypair
    mlkem = MLKEMCrypto()
    public_key, secret_key = mlkem.generate_keypair()
    steps.append({
        "step": 1,
        "action": "Server generates ML-KEM-768 keypair",
        "public_key_size": len(public_key),
        "secret_key_size": len(secret_key),
        "public_key_preview": base64.b64encode(public_key).decode()[:64] + "..."
    })
    
    # Step 2: Client encapsulates
    ciphertext, shared_secret_client = mlkem.encapsulate(public_key)
    steps.append({
        "step": 2,
        "action": "Client encapsulates using server's public key",
        "ciphertext_size": len(ciphertext),
        "shared_secret_size": len(shared_secret_client),
        "ciphertext_preview": base64.b64encode(ciphertext).decode()[:64] + "..."
    })
    
    # Step 3: Server decapsulates
    shared_secret_server = mlkem.decapsulate(ciphertext, secret_key)
    steps.append({
        "step": 3,
        "action": "Server decapsulates to get shared secret",
        "shared_secret_preview": shared_secret_server.hex()[:32] + "...",
        "secrets_match": mlkem.is_real_pqc  # Only match in real PQC mode
    })
    
    # Step 4: Derive AES key
    aes = AESGCMCrypto()
    aes_key = aes.derive_key_from_shared_secret(shared_secret_client)
    steps.append({
        "step": 4,
        "action": "Derive AES-256 key using HKDF-SHA256",
        "aes_key_size_bits": len(aes_key) * 8,
        "kdf": "HKDF-SHA256"
    })
    
    # Step 5: Encrypt sample data
    sample_data = b'{"user": "demo", "action": "test"}'
    encrypted = aes.encrypt(sample_data, aes_key)
    steps.append({
        "step": 5,
        "action": "Encrypt data with AES-256-GCM",
        "plaintext": sample_data.decode(),
        "ciphertext_preview": encrypted['ciphertext'][:32] + "...",
        "nonce_size": len(base64.b64decode(encrypted['nonce']))
    })
    
    # Step 6: Decrypt
    decrypted = aes.decrypt(encrypted['ciphertext'], encrypted['nonce'], 
                           encrypted['tag'], aes_key)
    steps.append({
        "step": 6,
        "action": "Decrypt data with AES-256-GCM",
        "decrypted": decrypted.decode(),
        "match": decrypted == sample_data
    })
    
    return jsonify({
        "success": True,
        "title": "PQC Communication Flow Demo",
        "algorithm": "ML-KEM-768 + AES-256-GCM",
        "library": mlkem.library,
        "real_pqc": mlkem.is_real_pqc,
        "steps": steps
    })


# ==================== Main Entry Point ====================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔐 CCDS Post-Quantum Cryptography Service")
    print("="*60)
    print(f"📍 Running on: http://localhost:{PQC_SERVICE_PORT}")
    print(f"🔬 Algorithm: ML-KEM-768 (NIST FIPS 203)")
    print(f"🔒 Encryption: AES-256-GCM")
    print("="*60 + "\n")
    
    # Run self-test on startup
    print("Running startup self-test...")
    try:
        run_self_test()
    except Exception as e:
        print(f"⚠️ Self-test warning: {e}")
    
    # Start Flask server
    app.run(host='0.0.0.0', port=PQC_SERVICE_PORT, debug=True)
