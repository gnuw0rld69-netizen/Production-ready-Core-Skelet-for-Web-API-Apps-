from ipaddress import ip_address

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import Sequence, cast

from .config import settings
from .database import get_db
from .security import InvalidTokenError, decode_token
from app.models.user import User, UserRole
from app.services.user_ip_allowlist_service import UserIpAllowlistService
from app.services.user_service import UserService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

async def get_current_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not token:
        raise credentials_exception()

    try:
        payload = decode_token(token)
    except InvalidTokenError:
        raise credentials_exception()

    user_id = payload.get("sub")
    token_type = payload.get("type")
    if token_type != "access":
        raise credentials_exception()
    if user_id is None:
        raise credentials_exception()

    try:
        user_id_int = int(cast(str, user_id))
    except (TypeError, ValueError):
        raise credentials_exception()

    user = UserService.get_by_id(db, user_id_int)
    if user is None:
        raise credentials_exception()

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email is not verified",
        )

    client_ip = _get_client_ip(request)
    if not UserIpAllowlistService.is_ip_allowed(db, user.id, client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address is not allowed",
        )

    return user


def _is_trusted_proxy(client_ip: str) -> bool:
    if not settings.TRUSTED_PROXY_IPS:
        return False
    for proxy in settings.TRUSTED_PROXY_IPS:
        try:
            if ip_address(client_ip) == ip_address(proxy):
                return True
        except ValueError:
            continue
    return False


def _get_client_ip(request: Request) -> str | None:
    if not request.client:
        return None
    client_ip = request.client.host
    if not _is_trusted_proxy(client_ip):
        return client_ip

    forwarded_for = request.headers.get("x-forwarded-for")
    if not forwarded_for:
        return client_ip
    forwarded_ip = forwarded_for.split(",", 1)[0].strip()
    return forwarded_ip or client_ip


def get_client_ip(request: Request) -> str | None:
    return _get_client_ip(request)

async def get_current_active_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.role != UserRole.SUPERUSER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

def role_required(required_roles: Sequence[UserRole]):
    allowed_roles = set(required_roles)

    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions"
            )
        return current_user

    return role_checker
