from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import Any, List, Optional

from app.core.database import get_db
from app.core.config import settings
from app.schemas.user import (
    PasswordChangeRequest,
    UserIpAllowlistCreate,
    UserIpAllowlistResponse,
    UserIpAllowlistUpdate,
    UserCreate,
    UserResponse,
    UserRoleUpdate,
    UserUpdate,
)
from app.services.auth_service import AuthService
from app.services.cache_service import CacheService
from app.services.email_service import EmailService
from app.services.user_ip_allowlist_service import UserIpAllowlistService
from app.services.user_service import UserService
from app.core.dependencies import get_current_user, get_current_active_superuser, role_required
from app.models.user import User, UserRole
from app.core.security import verify_password

router = APIRouter(prefix="/users", tags=["Users"])


def _ensure_self_or_admin(current_user: User, target_user_id: int) -> None:
    if current_user.id == target_user_id:
        return
    if current_user.role in {UserRole.ADMIN, UserRole.SUPERUSER}:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Not enough permissions",
    )

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    user_data: UserCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
) -> Any:
    """
    Register a new user
    """
    try:
        user = UserService.create_user(db, user_data)

        verification_token = AuthService.generate_email_verification_token(user)
        db.add(user)
        db.commit()

        verification_link = AuthService.build_email_verification_link(verification_token)
        email_subject, email_text, email_html = EmailService.build_verification_email(verification_link)
        background_tasks.add_task(
            EmailService.send_email,
            user.email,
            email_subject,
            email_text,
            email_html,
        )
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/", response_model=List[UserResponse])
def get_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    role: Optional[UserRole] = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER]))
) -> Any:
    """
    Get all users (admin only)
    """
    users = UserService.get_users(db, skip=skip, limit=limit, role=role)
    return users

@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get user by ID
    """
    _ensure_self_or_admin(current_user, user_id)

    cached_user = CacheService.get_user(user_id)
    if cached_user:
        return cached_user

    user = UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    response = UserResponse.model_validate(user).model_dump(mode="json")
    CacheService.set_user(user_id, response)
    return response

@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Update user
    """
    _ensure_self_or_admin(current_user, user_id)

    try:
        updated_user = UserService.update_user(db, user_id, user_data)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return updated_user

@router.post("/change-password")
def change_password(
    password_data: PasswordChangeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Change user password
    """
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password"
        )

    updated_user = UserService.update_user(
        db, 
        current_user.id, 
        UserUpdate(password=password_data.new_password)
    )
    
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {"message": "Password changed successfully"}

@router.put("/{user_id}/role", response_model=UserResponse)
def change_user_role(
    user_id: int,
    role_data: UserRoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser)
) -> Any:
    """
    Change user role (superuser only)
    """
    # Prevent changing own role
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own role"
        )
    
    updated_user = UserService.change_user_role(db, user_id, role_data.role)
    if not updated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return updated_user

@router.post("/{user_id}/deactivate")
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER]))
) -> Any:
    """
    Deactivate user (admin only)
    """
    # Prevent deactivating yourself
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate yourself"
        )
    
    user = UserService.deactivate_user(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {"message": "User deactivated successfully"}

@router.post("/{user_id}/activate")
def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER]))
) -> Any:
    """
    Activate user (admin only)
    """
    user = UserService.activate_user(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return {"message": "User activated successfully"}


@router.post("/{user_id}/verify-email")
def verify_user_email(
    user_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER])),
) -> Any:
    user = UserService.verify_email_manually(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"message": "Email verified successfully"}


@router.post("/{user_id}/2fa/disable")
def admin_disable_two_factor(
    user_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER])),
) -> Any:
    user = UserService.disable_two_factor(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return {"message": "2FA disabled successfully"}


@router.get("/me/allowed-ips", response_model=List[UserIpAllowlistResponse])
def list_allowed_ips(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    return UserIpAllowlistService.list_for_user(db, current_user.id)


@router.post("/me/allowed-ips", response_model=UserIpAllowlistResponse, status_code=status.HTTP_201_CREATED)
def create_allowed_ip(
    payload: UserIpAllowlistCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    try:
        return UserIpAllowlistService.create_entry(
            db,
            user_id=current_user.id,
            ip_or_network=payload.ip_or_network,
            description=payload.description,
            is_active=payload.is_active,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.put("/me/allowed-ips/{entry_id}", response_model=UserIpAllowlistResponse)
def update_allowed_ip(
    entry_id: int,
    payload: UserIpAllowlistUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    try:
        entry = UserIpAllowlistService.update_entry(
            db,
            user_id=current_user.id,
            entry_id=entry_id,
            ip_or_network=payload.ip_or_network,
            description=payload.description,
            is_active=payload.is_active,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Allowed IP entry not found",
        )
    return entry


@router.delete("/me/allowed-ips/{entry_id}")
def delete_allowed_ip(
    entry_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    deleted = UserIpAllowlistService.delete_entry(db, current_user.id, entry_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Allowed IP entry not found",
        )
    return {"message": "Allowed IP entry deleted"}


@router.get("/{user_id}/allowed-ips", response_model=List[UserIpAllowlistResponse])
def list_allowed_ips_for_user(
    user_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER])),
) -> Any:
    return UserIpAllowlistService.list_for_user(db, user_id)


@router.post(
    "/{user_id}/allowed-ips",
    response_model=UserIpAllowlistResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_allowed_ip_for_user(
    user_id: int,
    payload: UserIpAllowlistCreate,
    db: Session = Depends(get_db),
    _current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER])),
) -> Any:
    try:
        return UserIpAllowlistService.create_entry(
            db,
            user_id=user_id,
            ip_or_network=payload.ip_or_network,
            description=payload.description,
            is_active=payload.is_active,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.put("/{user_id}/allowed-ips/{entry_id}", response_model=UserIpAllowlistResponse)
def update_allowed_ip_for_user(
    user_id: int,
    entry_id: int,
    payload: UserIpAllowlistUpdate,
    db: Session = Depends(get_db),
    _current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER])),
) -> Any:
    try:
        entry = UserIpAllowlistService.update_entry(
            db,
            user_id=user_id,
            entry_id=entry_id,
            ip_or_network=payload.ip_or_network,
            description=payload.description,
            is_active=payload.is_active,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Allowed IP entry not found",
        )
    return entry


@router.delete("/{user_id}/allowed-ips/{entry_id}")
def delete_allowed_ip_for_user(
    user_id: int,
    entry_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(role_required([UserRole.ADMIN, UserRole.SUPERUSER])),
) -> Any:
    deleted = UserIpAllowlistService.delete_entry(db, user_id, entry_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Allowed IP entry not found",
        )
    return {"message": "Allowed IP entry deleted"}
