from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import json
import os
from database import init_db, get_db
from auth import hash_password, verify_password, generate_token, verify_token
from models import User, LicenseKey, ScanResult, AuditLog
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
CORS(app)

# Initialize database
init_db()

# ── API VERSION ──────────────────────────────────────────────────────────────
APP_VERSION = "1.0.0"
MIN_CLIENT_VERSION = "1.0.0"

# ── ENDPOINTS ────────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200

@app.route('/api/version', methods=['GET'])
def version():
    """Check app version and get update info"""
    return jsonify({
        "current_version": APP_VERSION,
        "min_version": MIN_CLIENT_VERSION,
        "update_required": False,
        "download_url": "https://example.com/download/client.exe"
    }), 200

@app.route('/api/register', methods=['POST'])
def register():
    """Register new account"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    role = data.get('role', 'user').lower()
    hwid = data.get('hwid', '')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    
    if role not in ['admin', 'user']:
        return jsonify({"error": "Invalid role"}), 400
    
    db = get_db()
    
    # Check if user exists
    user = db.query(User).filter_by(username=username).first()
    if user:
        return jsonify({"error": "Username already exists"}), 400
    
    # Create new user
    new_user = User(
        id=str(uuid.uuid4()),
        username=username,
        password_hash=hash_password(password),
        role=role,
        hwid=hwid if hwid else None,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=30)
    )
    
    db.add(new_user)
    db.commit()
    
    return jsonify({
        "success": True,
        "user_id": new_user.id,
        "message": "Account created successfully"
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    """Login user"""
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    hwid = data.get('hwid', '')
    master_password = data.get('master_password', '')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    db = get_db()
    user = db.query(User).filter_by(username=username).first()
    
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Check if account is locked
    if user.locked_until and datetime.utcnow() < user.locked_until:
        remaining = (user.locked_until - datetime.utcnow()).total_seconds() / 60
        return jsonify({"error": f"Account locked. Try again in {int(remaining)} minutes"}), 401
    
    # Verify password
    if not verify_password(password, user.password_hash):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.commit()
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Reset failed attempts
    user.failed_attempts = 0
    user.last_login = datetime.utcnow()
    
    # Check if account expired
    if user.expires_at and datetime.utcnow() > user.expires_at:
        return jsonify({"error": "Account expired"}), 401
    
    # Check HWID (except for owner)
    if user.role != 'owner':
        if user.hwid and user.hwid != hwid:
            return jsonify({"error": "HWID mismatch - unauthorized device"}), 401
        if not user.hwid:
            user.hwid = hwid
    
    # For owner, check master password
    if user.role == 'owner':
        if not master_password or master_password != user.master_password:
            return jsonify({"error": "Invalid master password"}), 401
    
    db.commit()
    
    # Generate token
    token = generate_token(user.id, user.role)
    
    return jsonify({
        "success": True,
        "token": token,
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "expires_at": user.expires_at.isoformat() if user.expires_at else None
    }), 200

@app.route('/api/owner/create-account', methods=['POST'])
def owner_create_account():
    """Owner creates admin or user account with optional license key"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id, role = verify_token(token)
    
    if not user_id or role != 'owner':
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    account_role = data.get('role', 'user').lower()
    generate_key = data.get('generate_license_key', False)
    expiry_days = data.get('expiry_days', 30)
    account_limit = data.get('account_limit', 10)
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    db = get_db()
    
    # Check if username exists
    if db.query(User).filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    
    # Create account
    new_user = User(
        id=str(uuid.uuid4()),
        username=username,
        password_hash=hash_password(password),
        role=account_role,
        created_by=user_id,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(days=expiry_days),
        account_limit=account_limit if account_role == 'admin' else None
    )
    
    db.add(new_user)
    db.commit()
    
    response = {
        "success": True,
        "user_id": new_user.id,
        "username": new_user.username,
        "role": new_user.role
    }
    
    # Generate license key if requested
    if generate_key and account_role == 'admin':
        key = LicenseKey(
            id=str(uuid.uuid4()),
            key=f"NOTA-{str(uuid.uuid4())[:8].upper()}",
            admin_id=new_user.id,
            account_limit=account_limit,
            expires_at=datetime.utcnow() + timedelta(days=365),
            created_by=user_id,
            created_at=datetime.utcnow()
        )
        db.add(key)
        db.commit()
        response["license_key"] = key.key
    
    # Log action
    audit = AuditLog(
        id=str(uuid.uuid4()),
        owner_id=user_id,
        action=f"Created {account_role} account: {username}",
        timestamp=datetime.utcnow()
    )
    db.add(audit)
    db.commit()
    
    return jsonify(response), 201

@app.route('/api/owner/accounts', methods=['GET'])
def owner_get_accounts():
    """Get all accounts (for owner)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id, role = verify_token(token)
    
    if not user_id or role != 'owner':
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    accounts = db.query(User).all()
    
    result = []
    for acc in accounts:
        result.append({
            "id": acc.id,
            "username": acc.username,
            "role": acc.role,
            "expires_at": acc.expires_at.isoformat() if acc.expires_at else None,
            "created_at": acc.created_at.isoformat(),
            "status": "active" if not acc.suspended else "suspended",
            "hwid": acc.hwid[:16] + "..." if acc.hwid else None,
            "last_login": acc.last_login.isoformat() if acc.last_login else None
        })
    
    return jsonify({"accounts": result}), 200

@app.route('/api/admin/users', methods=['GET'])
def admin_get_users():
    """Get users created by this admin"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id, role = verify_token(token)
    
    if not user_id or role != 'admin':
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    users = db.query(User).filter_by(created_by=user_id, role='user').all()
    
    result = []
    for user in users:
        result.append({
            "id": user.id,
            "username": user.username,
            "expires_at": user.expires_at.isoformat() if user.expires_at else None,
            "created_at": user.created_at.isoformat(),
            "status": "active" if not user.suspended else "suspended",
            "last_login": user.last_login.isoformat() if user.last_login else None
        })
    
    return jsonify({"users": result}), 200

@app.route('/api/scan/submit', methods=['POST'])
def submit_scan():
    """Submit scan results"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id, role = verify_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    findings = data.get('findings', [])
    scan_mode = data.get('mode', 'deep')
    
    db = get_db()
    
    scan = ScanResult(
        id=str(uuid.uuid4()),
        user_id=user_id,
        findings=json.dumps(findings),
        mode=scan_mode,
        timestamp=datetime.utcnow()
    )
    
    db.add(scan)
    db.commit()
    
    return jsonify({
        "success": True,
        "scan_id": scan.id
    }), 201

@app.route('/api/scan/results', methods=['GET'])
def get_scan_results():
    """Get scan results for current user"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    user_id, role = verify_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    db = get_db()
    
    if role == 'owner':
        scans = db.query(ScanResult).all()
    elif role == 'admin':
        # Get results from users they created
        user_ids = [u.id for u in db.query(User).filter_by(created_by=user_id).all()]
        scans = db.query(ScanResult).filter(ScanResult.user_id.in_(user_ids)).all()
    else:
        scans = db.query(ScanResult).filter_by(user_id=user_id).all()
    
    result = []
    for scan in scans:
        result.append({
            "id": scan.id,
            "user_id": scan.user_id,
            "findings": json.loads(scan.findings),
            "mode": scan.mode,
            "timestamp": scan.timestamp.isoformat()
        })
    
    return jsonify({"results": result}), 200

@app.route('/api/signatures', methods=['GET'])
def get_signatures():
    """Get latest cheat signatures"""
    # TODO: Load from JSON file or database
    signatures = {
        "hashes": {
            "e3b0c44298fc1c149afbf4c8996fb924": "Aimbot Pro",
            "a7ffc6f8bf1ed76651c14756a061d662": "Wallhack Engine"
        },
        "keywords": [
            "internal", "external", "panel", "xiter",
            "aimbot", "wallhack", "triggerbot", "spinbot"
        ],
        "updated_at": datetime.utcnow().isoformat()
    }
    return jsonify(signatures), 200

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
