# Models are defined in database.py
# This file is just a reference for the data structures

"""
User model:
- id: unique identifier
- username: login username
- password_hash: hashed password
- role: owner, admin, or user
- master_password: additional password for owner (optional)
- hwid: hardware ID for HWID lock
- created_at: account creation time
- created_by: who created this account
- expires_at: when account expires
- last_login: last login timestamp
- account_limit: max users an admin can create
- suspended: if account is banned
- locked_until: account lockout time after failed attempts
- failed_attempts: count of failed login attempts

LicenseKey model:
- id: unique identifier
- key: the actual license key (NOTA-ABC123-XYZ789)
- admin_id: which admin this key belongs to
- account_limit: how many users this key allows
- expires_at: when license expires
- created_at: when license was created
- created_by: which owner created this license
- is_active: if license is still valid

ScanResult model:
- id: unique identifier
- user_id: which user ran the scan
- findings: JSON string of detected items
- mode: quick, medium, or deep scan
- timestamp: when scan was run

AuditLog model:
- id: unique identifier
- owner_id: which owner performed the action
- action: description of what was done
- timestamp: when action occurred
"""
