from ipaddress import ip_address, ip_network

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime

from app.models.user import UserRole


def validate_password_strength(value: str) -> str:
    if not any(char.isdigit() for char in value):
        raise ValueError("Password must contain at least one digit")
    if not any(char.isupper() for char in value):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(char.islower() for char in value):
        raise ValueError("Password must contain at least one lowercase letter")
    return value

class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not value.isalnum():
            raise ValueError("Username must be alphanumeric")
        return value

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = Field(default=None, min_length=8)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: Optional[EmailStr]) -> Optional[str]:
        if value is None:
            return None
        return str(value).strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return validate_password_strength(value)

class UserInDB(UserBase):
    id: int
    role: UserRole
    is_active: bool
    is_verified: bool
    verified_at: Optional[datetime]
    is_two_factor_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)

class UserResponse(UserInDB):
    pass

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TwoFactorSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class TwoFactorVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        if not value.isdigit():
            raise ValueError("2FA code must contain only digits")
        return value

class TokenPayload(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None
    type: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str


class EmailVerificationRequest(BaseModel):
    token: str = Field(..., min_length=32)


class ResendVerificationRequest(BaseModel):
    email: EmailStr

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


class PasswordResetRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().lower()

class UserRoleUpdate(BaseModel):
    role: UserRole


class UserIpAllowlistBase(BaseModel):
    ip_or_network: str = Field(..., min_length=2, max_length=64)
    description: Optional[str] = Field(default=None, max_length=255)
    is_active: bool = True

    @field_validator("ip_or_network")
    @classmethod
    def validate_ip_or_network(cls, value: str) -> str:
        value = value.strip()
        try:
            if "/" in value:
                ip_network(value, strict=False)
            else:
                ip_address(value)
        except ValueError as exc:
            raise ValueError("Invalid IP address or network") from exc
        return value


class UserIpAllowlistCreate(UserIpAllowlistBase):
    pass


class UserIpAllowlistUpdate(BaseModel):
    ip_or_network: Optional[str] = Field(default=None, min_length=2, max_length=64)
    description: Optional[str] = Field(default=None, max_length=255)
    is_active: Optional[bool] = None

    @field_validator("ip_or_network")
    @classmethod
    def validate_ip_or_network(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        try:
            if "/" in value:
                ip_network(value, strict=False)
            else:
                ip_address(value)
        except ValueError as exc:
            raise ValueError("Invalid IP address or network") from exc
        return value


class UserIpAllowlistResponse(UserIpAllowlistBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)
