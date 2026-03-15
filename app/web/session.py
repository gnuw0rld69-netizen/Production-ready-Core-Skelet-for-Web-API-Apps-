from __future__ import annotations

from sqlalchemy.orm import Session
from fastapi import Request

from app.core.security import InvalidTokenError, decode_token
from app.core.dependencies import get_client_ip
from app.models.user import User
from app.services.auth_service import AuthService
from app.services.user_ip_allowlist_service import UserIpAllowlistService
from app.services.user_service import UserService


def get_current_user_from_cookie(
    request: Request,
    db: Session,
    require_verified: bool = True,
) -> User | None:
    token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")
    if not token:
        return None
    try:
        payload = decode_token(token)
    except InvalidTokenError:
        payload = None
        if refresh_token:
            new_access = AuthService.refresh_access_token(db, refresh_token)
            if new_access:
                request.state.new_access_token = new_access
                try:
                    payload = decode_token(new_access)
                except InvalidTokenError:
                    payload = None
        if payload is None:
            return None

    if payload.get("type") != "access":
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    try:
        user_id_int = int(str(user_id))
    except (TypeError, ValueError):
        return None

    user = UserService.get_by_id(db, user_id_int)
    if not user or not user.is_active:
        return None
    if require_verified and not user.is_verified:
        return None

    client_ip = get_client_ip(request)
    if not UserIpAllowlistService.is_ip_allowed(db, user.id, client_ip):
        return None
    return user
