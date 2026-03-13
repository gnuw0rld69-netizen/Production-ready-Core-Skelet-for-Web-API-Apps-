from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import datetime, timezone
import secrets
import string
from typing import Optional, List

from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import get_password_hash, verify_password
from app.services.cache_service import CacheService

class UserService:
    @staticmethod
    def _commit(db: Session) -> None:
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise

    @staticmethod
    def get_by_id(db: Session, user_id: int) -> Optional[User]:
        return db.query(User).filter(User.id == user_id).first()
    
    @staticmethod
    def get_by_email(db: Session, email: str) -> Optional[User]:
        normalized = email.strip().lower()
        return db.query(User).filter(User.email == normalized).first()
    
    @staticmethod
    def get_by_username(db: Session, username: str) -> Optional[User]:
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def get_by_username_or_email(db: Session, login: str) -> Optional[User]:
        return db.query(User).filter(
            or_(User.username == login, User.email == login)
        ).first()
    
    @staticmethod
    def get_users(
        db: Session, 
        skip: int = 0, 
        limit: int = 100,
        role: Optional[UserRole] = None
    ) -> List[User]:
        query = db.query(User)
        if role:
            query = query.filter(User.role == role)
        return query.offset(skip).limit(limit).all()
    
    @staticmethod
    def create_user(db: Session, user_data: UserCreate) -> User:
        email = user_data.email.strip().lower()
        if UserService.get_by_email(db, email):
            raise ValueError("Email already registered")
        if UserService.get_by_username(db, user_data.username):
            raise ValueError("Username already taken")

        db_user = User(
            email=email,
            username=user_data.username,
            full_name=user_data.full_name,
            hashed_password=get_password_hash(user_data.password),
            role=UserRole.USER
        )

        db.add(db_user)
        UserService._commit(db)
        db.refresh(db_user)
        CacheService.invalidate_user(db_user.id)
        return db_user

    @staticmethod
    def update_user(
        db: Session, 
        user_id: int, 
        user_data: UserUpdate
    ) -> Optional[User]:
        user = UserService.get_by_id(db, user_id)
        if not user:
            return None

        update_data = user_data.model_dump(exclude_unset=True)

        new_email = update_data.get("email")
        if new_email:
            update_data["email"] = new_email.strip().lower()
            new_email = update_data["email"]
        if new_email and new_email != user.email:
            existing_user = UserService.get_by_email(db, new_email)
            if existing_user and existing_user.id != user.id:
                raise ValueError("Email already registered")
            user.is_verified = False
            user.verified_at = None
            user.email_verification_token_hash = None
            user.email_verification_expires_at = None

        if "password" in update_data:
            update_data["hashed_password"] = get_password_hash(update_data.pop("password"))

        for field, value in update_data.items():
            setattr(user, field, value)

        UserService._commit(db)
        db.refresh(user)
        CacheService.invalidate_user(user.id)
        return user

    @staticmethod
    def authenticate_user(
        db: Session, 
        login: str, 
        password: str
    ) -> Optional[User]:
        user = UserService.get_by_username_or_email(db, login)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    @staticmethod
    def update_last_login(db: Session, user: User) -> None:
        user.last_login = datetime.now(timezone.utc)
        UserService._commit(db)
        CacheService.invalidate_user(user.id)

    @staticmethod
    def generate_random_password(length: int = 12) -> str:
        if length < 8:
            length = 8
        alphabet = string.ascii_letters + string.digits
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            if (
                any(char.isdigit() for char in password)
                and any(char.isupper() for char in password)
                and any(char.islower() for char in password)
            ):
                return password

    @staticmethod
    def reset_password_by_email(db: Session, email: str) -> tuple[User, str] | None:
        user = UserService.get_by_email(db, email)
        if not user:
            return None
        new_password = UserService.generate_random_password()
        user.hashed_password = get_password_hash(new_password)
        UserService._commit(db)
        db.refresh(user)
        CacheService.invalidate_user(user.id)
        return user, new_password

    @staticmethod
    def change_user_role(
        db: Session, 
        user_id: int, 
        new_role: UserRole
    ) -> Optional[User]:
        user = UserService.get_by_id(db, user_id)
        if not user:
            return None

        user.role = new_role
        UserService._commit(db)
        db.refresh(user)
        CacheService.invalidate_user(user.id)
        return user

    @staticmethod
    def deactivate_user(db: Session, user_id: int) -> Optional[User]:
        user = UserService.get_by_id(db, user_id)
        if not user:
            return None

        user.is_active = False
        UserService._commit(db)
        db.refresh(user)
        CacheService.invalidate_user(user.id)
        return user

    @staticmethod
    def activate_user(db: Session, user_id: int) -> Optional[User]:
        user = UserService.get_by_id(db, user_id)
        if not user:
            return None

        user.is_active = True
        UserService._commit(db)
        db.refresh(user)
        CacheService.invalidate_user(user.id)
        return user

    @staticmethod
    def disable_two_factor(db: Session, user_id: int) -> Optional[User]:
        user = UserService.get_by_id(db, user_id)
        if not user:
            return None

        user.is_two_factor_enabled = False
        user.two_factor_secret = None
        UserService._commit(db)
        db.refresh(user)
        CacheService.invalidate_user(user.id)
        return user

    @staticmethod
    def verify_email_manually(db: Session, user_id: int) -> Optional[User]:
        user = UserService.get_by_id(db, user_id)
        if not user:
            return None

        user.is_verified = True
        user.verified_at = datetime.now(timezone.utc)
        user.email_verification_token_hash = None
        user.email_verification_expires_at = None
        UserService._commit(db)
        db.refresh(user)
        CacheService.invalidate_user(user.id)
        return user
