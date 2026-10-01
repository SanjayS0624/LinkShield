from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import bcrypt
import jwt

from app.core.config import settings

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return False


def create_access_token(user_id: UUID, role: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": str(user_id), "role": role, "type": "access", "jti": str(uuid4()), "iat": now,
              "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes)}
    return jwt.encode(claims, settings.jwt_secret_key, algorithm=ALGORITHM)


def create_refresh_token(user_id: UUID) -> tuple[str, str, datetime]:
    now = datetime.now(timezone.utc)
    jti = str(uuid4())
    expires = now + timedelta(days=settings.jwt_refresh_token_expire_days)
    claims = {"sub": str(user_id), "jti": jti, "type": "refresh", "iat": now, "exp": expires}
    return jwt.encode(claims, settings.jwt_secret_key, algorithm=ALGORITHM), jti, expires


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[ALGORITHM], options={"require": ["exp", "iat", "sub", "type"]})
