"""System configuration and environment management for TTI."""

import base64
from functools import lru_cache
import hashlib
from typing import List, Union
from pydantic import AnyHttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with strong typing and environment validation."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # General Project Information
    TTI_ENV: str = "development"
    TTI_PROJECT_NAME: str = "Telegram Threat Intelligence (TTI)"
    TTI_API_V1_STR: str = "/api/v1"
    TTI_LOG_LEVEL: str = "INFO"
    TTI_SECRET_KEY: str = "dev_insecure_secret_key_must_be_changed_in_production_min32chars!"
    TTI_ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours session TTL (DEC-20)
    TTI_TOKEN_ALGORITHM: str = "HS256"

    # Multi-tenancy Architecture Baseline
    TTI_DEFAULT_TENANT_ID: str = "00000000-0000-0000-0000-000000000001"
    TTI_DEFAULT_TENANT_NAME: str = "Default Operations Tenant"

    # PostgreSQL Database Connection
    POSTGRES_USER: str = "tti_user"
    POSTGRES_PASSWORD: str = "tti_dev_password_change_in_production"
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "tti_dev"
    SQLALCHEMY_DATABASE_URI: str | None = None
    SQLALCHEMY_SYNC_DATABASE_URI: str | None = None

    # Redis Connection
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str | None = None
    REDIS_SOCKET_CONNECT_TIMEOUT: float = 1.0  # Fast-fail connect timeout (seconds)
    REDIS_SOCKET_TIMEOUT: float = 1.0          # Socket read/write timeout (seconds)
    REDIS_CIRCUIT_BREAKER_COOLDOWN: float = 30.0  # Cooldown before retry probe (seconds)

    # Telegram Bot & Ingestion Settings
    TELEGRAM_MODE: str = "webhook"  # webhook | polling
    TTI_TELEGRAM_BOT_TOKEN: str | None = None
    TTI_WEBHOOK_SECRET: str = "tti_dev_secret_token_1234567890_min32chars"
    TTI_WEBHOOK_URL: str | None = None
    TTI_TELEGRAM_PRIVACY_MODE: bool = True  # Non-negotiable privacy invariant

    # Cryptography & Identity Protection at Rest
    TTI_ID_PEPPER: str = "dev_pepper_secret_min32chars_change_in_production"
    TTI_DATA_ENCRYPTION_KEY: str | None = None
    TTI_CONSENT_RETENTION_MODE: str = "immediate"  # immediate | staged

    # Background Processing & Task Dispatcher
    TASK_DISPATCHER: str = "inline"            # "celery" | "inline"
    CELERY_BROKER_URL: str | None = None
    CELERY_RESULT_BACKEND: str | None = None
    CELERY_TASK_ALWAYS_EAGER: bool = False

    # Queue Concurrency Limits (Configurable per queue)
    CELERY_INGESTION_CONCURRENCY: int = 4
    CELERY_PROCESSING_CONCURRENCY: int = 4
    CELERY_DETECTION_CONCURRENCY: int = 2
    CELERY_NLP_CONCURRENCY: int = 2
    CELERY_FRAUD_CONCURRENCY: int = 2
    CELERY_URL_INTELLIGENCE_CONCURRENCY: int = 2
    CELERY_BEHAVIOUR_CONCURRENCY: int = 2
    CELERY_ALERTS_CONCURRENCY: int = 2
    CELERY_REPORTS_CONCURRENCY: int = 2
    CELERY_CLEANUP_CONCURRENCY: int = 1

    # Rate Limiting Configuration
    TTI_RATE_LIMIT_BACKEND: str = "memory"      # "redis" | "memory"
    TTI_RATE_LIMIT_LOGIN_IP_LIMIT: int = 10
    TTI_RATE_LIMIT_LOGIN_IP_WINDOW: int = 60
    TTI_RATE_LIMIT_LOGIN_ACCOUNT_LIMIT: int = 5
    TTI_RATE_LIMIT_LOGIN_ACCOUNT_WINDOW: int = 900

    # CORS Configuration
    TTI_BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    @field_validator("TTI_BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v  # type: ignore[return-value]
        raise ValueError(v)

    # Evidence Storage (must be isolated from frontend public directory)
    TTI_EVIDENCE_STORAGE_PATH: str = "./evidence_store"

    # Connector Operational Flags (Legacy stub flags)
    TTI_TELEGRAM_CONNECTOR_ACTIVE: bool = False
    TTI_DARKWEB_CONNECTOR_ACTIVE: bool = False
    TTI_LEGACY_INGEST_ENABLED: bool = False

    # Optional connector dummy parameters (never commit real tokens)
    TTI_TELEGRAM_API_ID: str | None = None
    TTI_TELEGRAM_API_HASH: str | None = None
    TTI_DARKWEB_SOCKS_PROXY: str = "socks5h://127.0.0.1:9050"

    # Telegram MTProto collection (user-authorized account)
    # Session string is a Telethon StringSession (authorized state only; never commit).
    TTI_MTPROTO_ENABLED: bool = False
    TTI_TELEGRAM_SESSION: str | None = None
    TTI_MTPROTO_POLL_INTERVAL_SECONDS: int = 30
    TTI_MTPROTO_HISTORICAL_LIMIT: int = 100     # messages fetched on first collection of a channel
    TTI_MTPROTO_BATCH_LIMIT: int = 100          # max messages per ingest_batch call
    TTI_MTPROTO_EDIT_LOOKBACK: int = 20         # re-read window for edit detection

    # Phase 3 Detection & Taxonomy Settings
    TTI_TAXONOMY_DIR: str = "backend/rules/taxonomy"
    TTI_DETECTION_MAX_TEXT_LENGTH: int = 4096
    TTI_DETECTION_REGEX_BUDGET_MS: float = 20.0
    TTI_DETECTION_CONTEXT_WINDOW_SIZE: int = 10

    # Google Gemini AI Threat Intelligence Configuration
    GEMINI_API_KEY: str | None = None
    GOOGLE_CLOUD_PROJECT_ID: str | None = None
    GEMINI_MODEL: str = "gemini-2.5-flash"
    GEMINI_PRO_MODEL: str = "gemini-2.5-pro"
    GEMINI_TEMPERATURE: float = 0.1
    GEMINI_MAX_TOKENS: int = 4096
    AI_CONFIDENCE_THRESHOLD: float = 40.0
    AI_AUTO_ANALYZE_LIVE: bool = True
    AI_ANOMALY_ZSCORE_THRESHOLD: float = 2.5
    AI_TOKEN_BUDGET_DAILY: int = 1_000_000

    # IOC Threat Enrichment Providers
    VIRUSTOTAL_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    OTX_API_KEY: str | None = None
    TTI_IOC_ENRICHMENT_API_KEY: str | None = None

    @model_validator(mode="after")
    def validate_security_and_environment(self) -> "Settings":
        """Enforce production security guards and validate runtime backend modes."""
        if self.TTI_RATE_LIMIT_BACKEND not in ("redis", "memory"):
            raise ValueError(f"Invalid TTI_RATE_LIMIT_BACKEND '{self.TTI_RATE_LIMIT_BACKEND}'; must be 'redis' or 'memory'")

        if self.TASK_DISPATCHER not in ("celery", "inline"):
            raise ValueError(f"Invalid TASK_DISPATCHER '{self.TASK_DISPATCHER}'; must be 'celery' or 'inline'")

        env_lower = self.TTI_ENV.lower()
        if env_lower == "production":
            insecure_secret = "dev_insecure_secret_key_must_be_changed_in_production_min32chars!"
            insecure_pw = "tti_dev_password_change_in_production"
            if self.TTI_SECRET_KEY == insecure_secret:
                raise ValueError("TTI_SECRET_KEY must be changed from default dev secret in production!")
            if len(self.TTI_SECRET_KEY) < 32:
                raise ValueError("TTI_SECRET_KEY must be at least 32 characters in production!")
            if self.POSTGRES_PASSWORD == insecure_pw:
                raise ValueError("POSTGRES_PASSWORD must be changed from default dev password in production!")
            if len(self.POSTGRES_PASSWORD) < 32:
                raise ValueError("POSTGRES_PASSWORD must be at least 32 characters in production!")
            if self.TTI_ID_PEPPER == "dev_pepper_secret_min32chars_change_in_production":
                raise ValueError("TTI_ID_PEPPER must be changed from dev default in production!")
            if len(self.TTI_ID_PEPPER) < 32:
                raise ValueError("TTI_ID_PEPPER must be at least 32 characters in production!")
            if self.TTI_WEBHOOK_SECRET == "tti_dev_secret_token_1234567890_min32chars":
                raise ValueError("TTI_WEBHOOK_SECRET must be changed in production!")
        return self

    @property
    def async_database_url(self) -> str:
        """Construct async PostgreSQL connection URL for SQLAlchemy asyncpg."""
        if self.SQLALCHEMY_DATABASE_URI:
            return self.SQLALCHEMY_DATABASE_URI
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def sync_database_url(self) -> str:
        """Construct sync PostgreSQL connection URL for Alembic migrations."""
        if self.SQLALCHEMY_SYNC_DATABASE_URI:
            return self.SQLALCHEMY_SYNC_DATABASE_URI
        return (
            f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def redis_url(self) -> str:
        """Construct Redis connection URL."""
        auth = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{auth}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def mtproto_credentials_configured(self) -> bool:
        """True when MTProto api_id/api_hash are present and syntactically valid."""
        return bool(
            self.TTI_TELEGRAM_API_ID
            and self.TTI_TELEGRAM_API_ID.isdigit()
            and self.TTI_TELEGRAM_API_HASH
            and len(self.TTI_TELEGRAM_API_HASH) == 32
        )

    @property
    def effective_celery_broker_url(self) -> str:
        """Return configured Celery broker URL or default to redis_url."""
        return self.CELERY_BROKER_URL or self.redis_url

    @property
    def effective_celery_result_backend(self) -> str:
        """Return configured Celery result backend URL or default to redis_url."""
        return self.CELERY_RESULT_BACKEND or self.redis_url

    @property
    def effective_encryption_key(self) -> bytes:
        """Return 32-byte urlsafe base64 key for Fernet, derived if not set."""
        if self.TTI_DATA_ENCRYPTION_KEY:
            return self.TTI_DATA_ENCRYPTION_KEY.encode()
        # Deterministically derive 32-byte Fernet key from TTI_SECRET_KEY
        digest = hashlib.sha256(self.TTI_SECRET_KEY.encode()).digest()
        return base64.urlsafe_b64encode(digest)


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
