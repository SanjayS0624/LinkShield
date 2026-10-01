from datetime import datetime, timezone
from uuid import UUID

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import current_user
from app.core.security import (create_access_token, create_refresh_token, decode_token,
                               hash_password, verify_password)
from app.database.session import get_db
from app.models.user import RefreshSession, User
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse, UserView

router = APIRouter(prefix="/api/auth", tags=["authentication"])


def issue_tokens(user: User, db: Session) -> TokenResponse:
    refresh_token, jti, expires_at = create_refresh_token(user.id)
    db.add(RefreshSession(jti=jti, user_id=user.id, expires_at=expires_at))
    db.flush()
    return TokenResponse(access_token=create_access_token(user.id, user.role), refresh_token=refresh_token, user=user)


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)) -> TokenResponse:
    email = str(payload.email).strip().lower()
    user = User(email=email, password_hash=hash_password(payload.password), role="viewer", is_active=True)
    db.add(user)
    try:
        db.flush()
        result = issue_tokens(user, db)
        db.commit()
        db.refresh(user)
        return result
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists") from None


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    email = str(payload.email).strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(payload.password, user.password_hash) or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password",
                            headers={"WWW-Authenticate": "Bearer"})
    result = issue_tokens(user, db)
    db.commit()
    return result


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        claims = decode_token(payload.refresh_token)
        if claims.get("type") != "refresh" or not claims.get("jti"):
            raise jwt.InvalidTokenError("wrong token type")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token") from None

    try:
        user_id = UUID(claims["sub"])
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token") from None
    session = db.scalar(select(RefreshSession).where(RefreshSession.jti == claims["jti"]).with_for_update())
    now = datetime.now(timezone.utc)
    if session is None or session.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    db.delete(session)
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    result = issue_tokens(user, db)
    db.commit()
    return result


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: RefreshRequest, db: Session = Depends(get_db)) -> None:
    try:
        claims = decode_token(payload.refresh_token)
    except jwt.InvalidTokenError:
        return
    if claims.get("type") == "refresh" and claims.get("jti"):
        session = db.get(RefreshSession, claims["jti"])
        if session is not None:
            db.delete(session)
            db.commit()


@router.get("/me", response_model=UserView)
def me(user: User = Depends(current_user)) -> User:
    return user
