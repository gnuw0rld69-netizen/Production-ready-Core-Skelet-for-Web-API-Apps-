from urllib.parse import quote_plus

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Database
    DB_USER: str
    DB_PASSWORD: str
    DB_HOST: str
    DB_PORT: int
    DB_NAME: str

    @property
    def DATABASE_URL(self) -> str:
        quoted_password = quote_plus(self.DB_PASSWORD)
        return (
            "mysql+pymysql://"
            f"{self.DB_USER}:{quoted_password}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    # JWT
    SECRET_KEY: str = Field(..., min_length=32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Security
    BCRYPT_ROUNDS: int = 12
    CORS_ORIGINS: list[AnyHttpUrl] = Field(default_factory=list)
    EMAIL_VERIFICATION_EXPIRE_HOURS: int = 24

    # Access control
    TRUSTED_PROXY_IPS: list[str] = Field(default_factory=list)


    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None
    REDIS_USE_SSL: bool = False

    @property
    def REDIS_URL(self) -> str:
        scheme = "rediss" if self.REDIS_USE_SSL else "redis"
        password_part = ""
        if self.REDIS_PASSWORD:
            quoted_password = quote_plus(self.REDIS_PASSWORD)
            password_part = f":{quoted_password}@"
        return f"{scheme}://{password_part}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, value: str | list[str] | None):
        if not value:
            return []
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("["):
                return value
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return value
        raise ValueError("Invalid CORS_ORIGINS format")

    @field_validator("TRUSTED_PROXY_IPS", mode="before")
    @classmethod
    def assemble_trusted_proxies(cls, value: str | list[str] | None):
        if not value:
            return []
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("["):
                return value
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, list):
            return value
        raise ValueError("Invalid TRUSTED_PROXY_IPS format")


    # App
    DEBUG: bool = False
    AUTO_CREATE_TABLES: bool = False
    PROJECT_NAME: str = "PROJECT_NAME"
    VERSION: str = "1.0.0"
    BACKEND_BASE_URL: str = "http://localhost:8000"

    # Web session
    WEB_SESSION_HOURS: int = 8

    # Cache
    CACHE_TTL_SECONDS: int = 60

    # SMTP
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_FROM_EMAIL: str = "no-reply@example.com"
    SMTP_FROM_NAME: str = "Auth Service"
    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False
    SMTP_TIMEOUT_SECONDS: int = 10

    # Turnstile
    TURNSTILE_SITE_KEY: str | None = None
    TURNSTILE_SECRET_KEY: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

settings = Settings()  # pyright: ignore[reportCallIssue]
