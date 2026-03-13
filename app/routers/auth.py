from typing import Annotated, Any, Optional

from email_validator import EmailNotValidError, validate_email

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.schemas.user import (
    EmailVerificationRequest,
    PasswordResetRequest,
    RefreshTokenRequest,
    ResendVerificationRequest,
    Token,
    TwoFactorSetupResponse,
    TwoFactorVerifyRequest,
    UserResponse,
)
from app.services.auth_service import AuthService
from app.services.email_service import EmailService
from app.services.user_service import UserService
from app.core.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


class OAuth2PasswordRequestFormWithOTP:
    def __init__(
        self,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
        scope: Annotated[str, Form()] = "",
        grant_type: Annotated[str | None, Form(pattern="^password$")] = None,
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
        secret_code: Annotated[Optional[str], Form()] = None,
        otp_code: Annotated[Optional[str], Form()] = None,
    ) -> None:
        self.username = username
        self.password = password
        self.scopes = scope.split()
        self.client_id = client_id
        self.client_secret = client_secret
        self.grant_type = grant_type
        otp_candidate = otp_code or secret_code or client_secret or client_id
        self.otp_code = otp_candidate.strip() if otp_candidate else None


def _send_verification_email(background_tasks: BackgroundTasks, email: str, token: str) -> None:
    verification_link = AuthService.build_email_verification_link(token)
    email_subject, email_text, email_html = EmailService.build_verification_email(verification_link)
    background_tasks.add_task(
        EmailService.send_email,
        email,
        email_subject,
        email_text,
        email_html,
    )


def _verify_email(db: Session, token: str) -> dict[str, str]:
    verified_user = AuthService.verify_email_token(db, token)
    if not verified_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )
    return {"message": "Email verified successfully"}

@router.post("/login", response_model=Token)
def login(
    login_data: OAuth2PasswordRequestFormWithOTP = Depends(),
    db: Session = Depends(get_db)
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    try:
        normalized_email = validate_email(login_data.username).email
    except EmailNotValidError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required for login",
        )

    user = AuthService.authenticate_user(
        db,
        normalized_email,
        login_data.password,
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
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

    if user.is_two_factor_enabled:
        if not login_data.otp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="2FA code required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not AuthService.verify_two_factor_code(user, login_data.otp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    # Update last login
    UserService.update_last_login(db, user)
    
    return AuthService.create_tokens(user)

@router.post("/refresh", response_model=Token)
def refresh_access_token(
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
) -> Any:
    """
    Refresh access token using refresh token
    """
    new_access_token = AuthService.refresh_access_token(db, refresh_data.refresh_token)
    
    if not new_access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Return new tokens (keeping same refresh token)
    return Token(
        access_token=new_access_token,
        refresh_token=refresh_data.refresh_token
    )

@router.post("/logout")
def logout(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Logout user (client should discard tokens)
    """
    return {"message": "Successfully logged out"}

@router.get("/me", response_model=UserResponse)
def read_users_me(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get current user
    """
    return current_user


@router.get("/verify-email")
def verify_email_by_query(
    token: str = Query(..., min_length=32),
    db: Session = Depends(get_db),
) -> Any:
    return _verify_email(db, token)


@router.post("/verify-email")
def verify_email_by_payload(
    payload: EmailVerificationRequest,
    db: Session = Depends(get_db),
) -> Any:
    return _verify_email(db, payload.token)


@router.post("/resend-verification")
def resend_email_verification(
    payload: ResendVerificationRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Any:
    user = UserService.get_by_email(db, payload.email)
    if user and not user.is_verified:
        token = AuthService.generate_email_verification_token(user)
        db.add(user)
        db.commit()
        _send_verification_email(background_tasks, user.email, token)

    return {"message": "If your account exists, a verification email was sent"}


@router.post("/reset-password")
def reset_password(
    payload: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> Any:
    result = UserService.reset_password_by_email(db, payload.email)
    if result:
        user, new_password = result
        subject, text_body, html_body = EmailService.build_password_reset_email(new_password)
        background_tasks.add_task(EmailService.send_email, user.email, subject, text_body, html_body)
    return {"message": "If your account exists, a new password was sent"}


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
def setup_two_factor(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    if current_user.is_two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is already enabled",
        )

    secret = AuthService.generate_two_factor_secret()
    current_user.two_factor_secret = secret
    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    provisioning_uri = AuthService.get_two_factor_provisioning_uri(current_user, secret)
    return TwoFactorSetupResponse(secret=secret, provisioning_uri=provisioning_uri)


@router.post("/2fa/enable")
def enable_two_factor(
    payload: TwoFactorVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    if current_user.is_two_factor_enabled:
        return {"message": "2FA is already enabled"}
    if not current_user.two_factor_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA setup is required before enabling",
        )
    if not AuthService.verify_two_factor_code(current_user, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code",
        )

    current_user.is_two_factor_enabled = True
    db.add(current_user)
    db.commit()
    return {"message": "2FA enabled successfully"}


@router.post("/2fa/disable")
def disable_two_factor(
    payload: TwoFactorVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    if not current_user.is_two_factor_enabled:
        return {"message": "2FA is not enabled"}
    if not AuthService.verify_two_factor_code(current_user, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code",
        )

    current_user.is_two_factor_enabled = False
    current_user.two_factor_secret = None
    db.add(current_user)
    db.commit()
    return {"message": "2FA disabled successfully"}
