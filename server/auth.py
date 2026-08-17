# auth.py
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import os
import redis
import json
from server_config import API_KEY, REDIS_URL

SECRET_KEY = API_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

_refresh_store = {}  # fallback in-memory store
_use_redis = False
_redis_client = None
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")

# Conexión a Redis para refresh tokens y rate limiting
redis_client = redis.from_url(REDIS_URL) if REDIS_URL else None

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def set_refresh_store(redis_client=None):
    global _use_redis, _redis_client
    if redis_client:
        _use_redis = True
        _redis_client = redis_client
    else:
        _use_redis = False

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    refresh_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    username = data.get("sub")
    if _use_redis and _redis_client:
        _redis_client.setex(f"refresh:{username}", REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600, refresh_token)
    else:
        _refresh_store[username] = refresh_token
    return refresh_token

def verify_token(token: str, expected_type: str = "access"):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != expected_type:
            return None
        return payload
    except JWTError:
        return None

def refresh_access_token(refresh_token: str):
    payload = verify_token(refresh_token, expected_type="refresh")
    if not payload:
        return None
    username = payload.get("sub")
    if not username:
        return None
    if _use_redis and _redis_client:
        stored = _redis_client.get(f"refresh:{username}")
        if not stored or stored.decode() != refresh_token:
            return None
    else:
        stored = _refresh_store.get(username)
        if stored != refresh_token:
            return None
    new_access = create_access_token({"sub": username})
    return new_access

def revoke_refresh_token(username: str):
    if _use_redis and _redis_client:
        _redis_client.delete(f"refresh:{username}")
    else:
        _refresh_store.pop(username, None)









