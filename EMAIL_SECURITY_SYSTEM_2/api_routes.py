"""
RESTful API Routes for Email Security Module
Clean API interface for integration with larger system
"""

from flask import Blueprint, request, jsonify, session
from functools import wraps
from email_security_module import EmailSecurityModule
from backend.db.db_utils import fetch_one
import jwt
from datetime import datetime, timedelta

# Create Blueprint
api_bp = Blueprint('api', __name__, url_prefix='/email-security/api/v1')

# Initialize module
email_module = EmailSecurityModule()

# Secret key for JWT (should be in config)
JWT_SECRET = 'email-security-jwt-secret-2024'


# ==================== AUTHENTICATION DECORATOR ====================

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check session-based auth (current system)
        if 'user_id' in session:
            request.user_id = session['user_id']
            return f(*args, **kwargs)
        
        # Check JWT token (for integration)
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if token:
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
                request.user_id = payload['user_id']
                return f(*args, **kwargs)
            except jwt.InvalidTokenError:
                pass
        
        return jsonify({'error': 'Authentication required'}), 401
    
    return decorated_function


# ==================== EMAIL ANALYSIS ====================

@api_bp.route('/analyze', methods=['POST'])
@require_auth
def analyze_email():
    """
    Analyze email for threats
    
    POST /email-security/api/v1/analyze
    Body: {
        "sender": "test@example.com",
        "subject": "Test Subject",
        "body": "Email body",
        "urls": ["http://example.com"],
        "attachments": ["file.pdf"]
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Analyze email
        result = email_module.analyze_email(data)
        
        return jsonify({
            'success': True,
            'analysis': result,
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== THREAT MANAGEMENT ====================

@api_bp.route('/threats', methods=['GET'])
@require_auth
def get_threats():
    """
    Get detected threats
    
    GET /email-security/api/v1/threats?user_id=123&timeframe=24h
    """
    try:
        filters = {
            'user_id': request.args.get('user_id', type=int),
            'severity': request.args.get('severity'),
            'timeframe': request.args.get('timeframe', '24h')
        }
        
        # Remove None values
        filters = {k: v for k, v in filters.items() if v is not None}
        
        threats = email_module.get_threats(filters)
        
        return jsonify({
            'success': True,
            'count': len(threats),
            'threats': threats
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/threats/<int:threat_id>', methods=['GET'])
@require_auth
def get_threat_detail(threat_id):
    """
    Get specific threat details
    
    GET /email-security/api/v1/threats/123
    """
    try:
        threat = email_module.get_threat_by_id(threat_id)
        
        if not threat:
            return jsonify({'error': 'Threat not found'}), 404
        
        return jsonify({
            'success': True,
            'threat': threat
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== STATISTICS ====================

@api_bp.route('/statistics', methods=['GET'])
@require_auth
def get_statistics():
    """
    Get module statistics
    
    GET /email-security/api/v1/statistics?user_id=123&timeframe=7d
    """
    try:
        user_id = request.args.get('user_id', type=int)
        timeframe = request.args.get('timeframe', '24h')
        
        stats = email_module.get_statistics(user_id, timeframe)
        
        return jsonify({
            'success': True,
            'statistics': stats
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== USER MANAGEMENT ====================

@api_bp.route('/users/profile', methods=['GET'])
@require_auth
def get_user_profile():
    """
    Get user profile
    
    GET /email-security/api/v1/users/profile
    """
    try:
        user_id = request.user_id
        profile = email_module.get_user_profile(user_id)
        
        if not profile:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'profile': profile
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/users/emails', methods=['GET'])
@require_auth
def get_user_emails():
    """
    Get user's emails
    
    GET /email-security/api/v1/users/emails?limit=50
    """
    try:
        user_id = request.user_id
        limit = request.args.get('limit', 50, type=int)
        
        emails = email_module.get_user_emails(user_id, limit)
        
        return jsonify({
            'success': True,
            'count': len(emails),
            'emails': emails
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== AUTHENTICATION ====================

@api_bp.route('/auth/token', methods=['POST'])
def generate_token():
    """
    Generate JWT token for API access
    
    POST /email-security/api/v1/auth/token
    Body: {
        "username": "user",
        "password": "pass"
    }
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        # Verify credentials (simplified - use proper auth)
        user = fetch_one(
            "SELECT id, username FROM users WHERE username = %s",
            (username,)
        )
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate JWT token
        payload = {
            'user_id': user['id'],
            'username': user['username'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        
        return jsonify({
            'success': True,
            'token': token,
            'expires_in': 86400  # 24 hours
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== HEALTH & MONITORING ====================

@api_bp.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint
    
    GET /email-security/api/v1/health
    """
    health = email_module.health_check()
    status_code = 200 if health['status'] == 'healthy' else 503
    return jsonify(health), status_code


@api_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """
    Get module metrics (Prometheus format)
    
    GET /email-security/api/v1/metrics
    """
    try:
        metrics = email_module.get_metrics()
        
        # Convert to Prometheus format
        prometheus_format = []
        for key, value in metrics.items():
            prometheus_format.append(f"{key} {value}")
        
        return '\n'.join(prometheus_format), 200, {'Content-Type': 'text/plain'}
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== EVENT WEBHOOK ====================

@api_bp.route('/events/webhook', methods=['POST'])
def receive_event():
    """
    Receive events from other modules
    
    POST /email-security/api/v1/events/webhook
    Body: {
        "module": "insider_threat",
        "event_type": "suspicious_activity",
        "data": {...}
    }
    """
    try:
        event = request.get_json()
        
        # Process event (implement your logic)
        # For example: correlate with email threats
        
        return jsonify({
            'success': True,
            'message': 'Event received',
            'event_id': event.get('id')
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== API DOCUMENTATION ====================

@api_bp.route('/docs', methods=['GET'])
def api_docs():
    """
    API documentation endpoint
    
    GET /email-security/api/v1/docs
    """
    docs = {
        'module': 'Email Security',
        'version': '1.0.0',
        'endpoints': {
            'POST /analyze': 'Analyze email for threats',
            'GET /threats': 'Get detected threats',
            'GET /threats/{id}': 'Get threat details',
            'GET /statistics': 'Get module statistics',
            'GET /users/profile': 'Get user profile',
            'GET /users/emails': 'Get user emails',
            'POST /auth/token': 'Generate JWT token',
            'GET /health': 'Health check',
            'GET /metrics': 'Module metrics',
            'POST /events/webhook': 'Receive events from other modules'
        },
        'authentication': 'JWT Bearer token or session-based',
        'base_url': '/email-security/api/v1'
    }
    
    return jsonify(docs), 200
