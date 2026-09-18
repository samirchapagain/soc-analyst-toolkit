import os
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

SECRET = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    try:
        return pwd_context.hash(password)
    except Exception:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()
        return f"pbkdf2${salt.hex()}${digest}"

def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2$"):
        _, salt, digest = stored.split("$", 2)
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex(), digest)
    try:
        return pwd_context.verify(password, stored)
    except Exception:
        return False

def create_token(user_id: int, email: str, role: str) -> str:
    return jwt.encode({"sub": str(user_id), "email": email, "role": role, "exp": datetime.now(timezone.utc) + timedelta(minutes=EXPIRE_MINUTES)}, SECRET, algorithm=ALGORITHM)

def current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials: raise HTTPException(401, "Authentication required")
    try:
        return jwt.decode(credentials.credentials, SECRET, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")

def require_roles(*roles):
    def dependency(user=Depends(current_user)):
        if roles and user.get("role") not in roles: raise HTTPException(403, "Insufficient role")
        return user
    return dependency
