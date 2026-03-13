import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from typing import Optional
from urllib.parse import quote

import pyotp

from app.models.user import User
from app.schemas.user import Token
from app.core.security import (
    InvalidTokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.services.cache_service import CacheService
from app.services.user_service import UserService
from app.core.config import settings

class AuthService:
    @staticmethod
    def authenticate_user(
        db: Session, 
        email: str, 
        password: str
    ) -> Optional[User]:
        """Authenticate user by email and password"""
        return UserService.authenticate_user(db, email, password)
    
    @staticmethod
    def create_tokens(user: User) -> Token:
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        access_token = create_access_token(
            data={"sub": str(user.id), "role": user.role.value},
            expires_delta=access_token_expires
        )

        refresh_token = create_refresh_token(
            data={"sub": str(user.id)}
        )

        return Token(
            access_token=access_token,
            refresh_token=refresh_token
        )

    @staticmethod
    def generate_email_verification_token(user: User) -> str:
        token = secrets.token_urlsafe(48)
        user.email_verification_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        user.email_verification_expires_at = datetime.now(timezone.utc) + timedelta(
            hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS
        )
        return token

    @staticmethod
    def build_email_verification_link(token: str) -> str:
        return f"{settings.BACKEND_BASE_URL}/api/v1/auth/verify-email?token={quote(token)}"

    @staticmethod
    def verify_email_token(db: Session, token: str) -> Optional[User]:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        user = db.query(User).filter(User.email_verification_token_hash == token_hash).first()
        if not user:
            return None

        if user.email_verification_expires_at is None:
            return None

        expires_at = user.email_verification_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            return None

        user.is_verified = True
        user.verified_at = datetime.now(timezone.utc)
        user.email_verification_token_hash = None
        user.email_verification_expires_at = None
        db.add(user)
        db.commit()
        db.refresh(user)
        CacheService.invalidate_user(user.id)
        return user

    @staticmethod
    def generate_two_factor_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_two_factor_provisioning_uri(user: User, secret: str) -> str:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=user.email, issuer_name=settings.PROJECT_NAME)

    @staticmethod
    def verify_two_factor_code(user: User, code: str) -> bool:
        if not user.two_factor_secret:
            return False
        totp = pyotp.TOTP(user.two_factor_secret)
        return bool(totp.verify(code, valid_window=1))

    @staticmethod
    def refresh_access_token(db: Session, refresh_token: str) -> Optional[str]:
        try:
            payload = decode_token(refresh_token)
        except InvalidTokenError:
            return None

        if payload.get("type") != "refresh":
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        try:
            user_id_int = int(user_id)
        except (TypeError, ValueError):
            return None

        user = UserService.get_by_id(db, user_id_int)
        if user is None or not user.is_active or not user.is_verified:
            return None

        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        return create_access_token(
            data={"sub": str(user.id), "role": user.role.value},
            expires_delta=access_token_expires
        )

    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        try:
            return decode_token(token)
        except InvalidTokenError:
            return None
