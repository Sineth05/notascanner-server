# NOTA Scanner Server

Backend server for NOTA Scanner anti-cheat detection system.

## Features
- User authentication with role-based access (Owner/Admin/User)
- License key management
- Scan result storage
- HWID locking
- Account expiry management
- Audit logging

## Setup

### Local Development
```bash
pip install -r requirements.txt
export SECRET_KEY="your-secret-key"
python app.py
```

### Production (Render)
1. Fork/clone this repo
2. Deploy to Render
3. Set environment variables:
   - `SECRET_KEY`: Your secret key
   - `DATABASE_URL`: PostgreSQL connection string (auto-provided by Render)

## API Endpoints

### Auth
- `POST /api/register` - Register new user
- `POST /api/login` - Login user

### Owner
- `POST /api/owner/create-account` - Create admin/user account
- `GET /api/owner/accounts` - Get all accounts

### Admin
- `GET /api/admin/users` - Get users created by admin

### Scan
- `POST /api/scan/submit` - Submit scan results
- `GET /api/scan/results` - Get scan results

### Other
- `GET /api/version` - Check app version
- `GET /api/signatures` - Get cheat signatures
- `GET /health` - Health check

## License
Private - NOTA Scanner
