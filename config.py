"""Application configuration and environment validation."""

import base64
import hashlib
import os
from datetime import timedelta


class Config:
    """Environment-backed configuration for local and production deployments."""

    ENVIRONMENT = os.environ.get("APP_ENV", "development").strip().lower()
    if ENVIRONMENT not in {"development", "production"}:
        raise RuntimeError("APP_ENV must be either 'development' or 'production'.")
    DEVELOPMENT = ENVIRONMENT != "production"
    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY:
        if DEVELOPMENT:
            SECRET_KEY = "local-development-only-change-before-deployment"
        else:
            raise RuntimeError("SECRET_KEY must be configured in production.")

    DATABASE_PATH = os.environ.get("DATABASE_PATH", "banking_demo.sqlite3")
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "Xanuhas").strip().casefold()
    TEMPLATES_AUTO_RELOAD = DEVELOPMENT
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = not DEVELOPMENT
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    MAX_CONTENT_LENGTH = 3 * 1024 * 1024
    PASSWORD_ITERATIONS = 600_000
    BCRYPT_ROUNDS = 12
    LOGIN_LOCKOUT_ATTEMPTS = 3
    LOGIN_LOCKOUT_SECONDS = 15 * 60
    LOGIN_VELOCITY_WINDOW_SECONDS = 5 * 60
    LOGIN_CHALLENGE_SECONDS = 5 * 60
    PAYMENT_PIN_MAX_ATTEMPTS = 3
    PAYMENT_PIN_LOCKOUT_SECONDS = 15 * 60
    MFA_RECOVERY_CODE_COUNT = 10
    MFA_MAX_ATTEMPTS = 5
    MFA_LOCKOUT_SECONDS = 15 * 60
    HIGH_VALUE_TRANSFER_CENTS = 100_000
    MAX_PROFILE_IMAGE_BYTES = 2 * 1024 * 1024
    PROFILE_IMAGE_DIR = os.environ.get(
        "PROFILE_IMAGE_DIR",
        os.path.join(os.path.dirname(__file__), "instance", "profile-images"),
    )
    PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    MAX_TRANSFER_CENTS = 100_000_000

    _encryption_key = os.environ.get("ENCRYPTION_KEY")
    if _encryption_key:
        try:
            ENCRYPTION_KEY = base64.urlsafe_b64decode(
                _encryption_key.encode("ascii") + b"=" * (-len(_encryption_key) % 4)
            )
        except (ValueError, UnicodeEncodeError) as exc:
            raise RuntimeError("ENCRYPTION_KEY must be URL-safe base64.") from exc
        if len(ENCRYPTION_KEY) != 32:
            raise RuntimeError("ENCRYPTION_KEY must decode to exactly 32 bytes.")
    elif DEVELOPMENT:
        ENCRYPTION_KEY = hashlib.sha256(
            b"local-only-demo-key-do-not-use-in-production"
        ).digest()
    else:
        raise RuntimeError("ENCRYPTION_KEY must be configured in production.")
