"""
backend/auth/auth_utils.py
Authentication helpers: password hashing and user authentication.
Extracted from app.py to keep the Flask app lean.
"""
import hashlib
from backend.db.db_utils import fetch_one


def hash_password(password: str) -> str:
    """Return SHA-256 hex digest of the password."""
    return hashlib.sha256(password.encode()).hexdigest()


def authenticate_user(username: str, password: str):
    """
    Authenticate a user against the database.
    Falls back to hardcoded admin credentials as a last resort.

    Returns a user dict on success, None on failure.
    """
    try:
        hashed = hash_password(password)

        # Try hash-based auth first (preferred)
        user = fetch_one(
            "SELECT * FROM users WHERE username = %s AND password_hash = %s",
            (username, hashed)
        )

        if not user:
            # Fallback: plain-text password field (legacy rows)
            user = fetch_one(
                "SELECT * FROM users WHERE username = %s AND password = %s",
                (username, password)
            )

        if user:
            # Always override email for the admin account
            email = (
                'rushabhkirad@gmail.com'
                if user['username'] == 'admin'
                else user.get('email')
            )
            return {
                'id':        user['id'],
                'username':  user['username'],
                'email':     email,
                'full_name': user.get('full_name', 'Administrator'),
            }

    except Exception as e:
        print(f"Database auth error: {e}")

    # Last-resort hardcoded admin check
    if username == 'admin' and password == 'admin123':
        return {
            'id':        61,
            'username':  'admin',
            'email':     'rushabhkirad@gmail.com',
            'full_name': 'Administrator',
        }

    return None
