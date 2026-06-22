import hashlib
import secrets
from datetime import datetime, timedelta
import jwt
import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${pwd_hash.hex()}"

def verify_password(password: str, hash_value: str) -> bool:
    """Verify password against hash"""
    try:
        salt, pwd_hash = hash_value.split('$')
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return new_hash.hex() == pwd_hash
    except:
        return False

def generate_token(user_id: str, role: str) -> str:
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token: str) -> tuple:
    """Verify JWT token and return (user_id, role)"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload.get('user_id'), payload.get('role')
    except:
        return None, None
