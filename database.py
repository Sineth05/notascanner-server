from sqlalchemy import create_engine, Column, String, DateTime, Integer, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///notascanner.db')

# Handle Postgres URL format
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String)  # owner, admin, user
    master_password = Column(String, nullable=True)  # Only for owner
    hwid = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, nullable=True)  # Which owner/admin created this
    expires_at = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    account_limit = Column(Integer, nullable=True)  # For admins
    suspended = Column(Boolean, default=False)
    locked_until = Column(DateTime, nullable=True)
    failed_attempts = Column(Integer, default=0)

class LicenseKey(Base):
    __tablename__ = "license_keys"
    
    id = Column(String, primary_key=True)
    key = Column(String, unique=True, index=True)
    admin_id = Column(String)
    account_limit = Column(Integer)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String)
    is_active = Column(Boolean, default=True)

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(String, primary_key=True)
    user_id = Column(String, index=True)
    findings = Column(Text)  # JSON string
    mode = Column(String)  # quick, medium, deep
    timestamp = Column(DateTime, default=datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(String, primary_key=True)
    owner_id = Column(String)
    action = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        return db
    except:
        db.close()
        raise
