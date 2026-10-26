"""TOTP and backup-code helpers for step-up authentication."""

import hashlib
import hmac
import secrets
import time

import pyotp
from flask import current_app


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_name: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=account_name,
        issuer_name="FinBest",
    )


def valid_totp_counter(secret: str, token: str, now: int | None = None) -> int | None:
    """Return an unused-window candidate counter after checking a six-digit TOTP."""
    if len(token) != 6 or not token.isascii() or not token.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    current_counter = int((time.time() if now is None else now) // totp.interval)
    for counter in (current_counter, current_counter - 1, current_counter + 1):
        if counter >= 0 and hmac.compare_digest(totp.generate_otp(counter), token):
            return counter
    return None


def generate_recovery_codes(count: int = 10) -> list[str]:
    return [secrets.token_hex(8).upper() for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    normalized = "".join(character for character in code.upper() if character.isalnum())
    key = current_app.config["SECRET_KEY"].encode("utf-8")
    return hmac.new(
        key,
        hashlib.sha256(normalized.encode("utf-8")).digest(),
        hashlib.sha256,
    ).hexdigest()
