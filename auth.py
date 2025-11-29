"""
Authentication utilities: password hashing, JWT tokens, OAuth.
"""
import os
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional
import bcrypt
from jose import JWTError, jwt

# JWT settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days


def hash_password(password: str) -> str:
    """Hash a password using bcrypt"""
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create JWT access token.
    
    Args:
        data: Payload data (usually {"sub": user_email})
        expires_delta: Token expiration time
    
    Returns:
        JWT token string
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """
    Decode and verify JWT token.
    
    Returns:
        Decoded payload or None if invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def generate_verification_token() -> str:
    """Generate random token for email verification"""
    return secrets.token_urlsafe(32)


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate API key for ENTERPRISE users.
    
    Returns:
        (full_key, key_hash, prefix) tuple
        - full_key: Show to user once (save this!)
        - key_hash: Store in database
        - prefix: First 8 chars for display
    """
    full_key = f"ba_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    prefix = full_key[:8]
    return full_key, key_hash, prefix


def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """Verify API key against stored hash"""
    provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
    return provided_hash == stored_hash
