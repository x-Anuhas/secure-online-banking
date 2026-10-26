"""Password, payment PIN, sensitive-data, and output-sanitization helpers."""

import hashlib
import hmac
import secrets

import bleach
import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Hash a password with bcrypt over a fixed-length SHA-256 prehash."""
    if salt is not None:
        return _hash_legacy_pbkdf2(password, salt)
    prehash = hashlib.sha256(password.encode("utf-8")).digest()
    encoded_hash = bcrypt.hashpw(
        prehash,
        bcrypt.gensalt(rounds=current_app.config["BCRYPT_ROUNDS"]),
    ).decode("ascii")
    return encoded_hash[:29], encoded_hash


def _hash_legacy_pbkdf2(password: str, salt: bytes) -> tuple[str, str]:
    """Recompute legacy PBKDF2 hashes so existing accounts can still be verified."""
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        current_app.config["PASSWORD_ITERATIONS"],
        dklen=32,
    )
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, expected_hex: str) -> bool:
    """Verify current bcrypt hashes and legacy PBKDF2 hashes in constant time."""
    if expected_hex.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(
                hashlib.sha256(password.encode("utf-8")).digest(),
                expected_hex.encode("ascii"),
            )
        except (UnicodeEncodeError, ValueError):
            return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    _, actual_hex = _hash_legacy_pbkdf2(password, salt)
    return hmac.compare_digest(bytes.fromhex(actual_hex), expected)


def is_bcrypt_password_hash(encoded_hash: str) -> bool:
    """Return whether a stored password hash uses one of bcrypt's supported prefixes."""
    return encoded_hash.startswith(("$2a$", "$2b$", "$2y$"))


def encrypt_sensitive_value(value: str) -> bytes:
    """Encrypt a sensitive field using AES-256-GCM and a unique nonce."""
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(current_app.config["ENCRYPTION_KEY"])
    return nonce + cipher.encrypt(nonce, value.encode("utf-8"), None)


def decrypt_sensitive_value(ciphertext: bytes) -> str:
    """Decrypt a value produced by :func:`encrypt_sensitive_value`."""
    if len(ciphertext) < 29:
        raise ValueError("Encrypted value is malformed.")
    cipher = AESGCM(current_app.config["ENCRYPTION_KEY"])
    return cipher.decrypt(ciphertext[:12], ciphertext[12:], None).decode("utf-8")


def sanitize_plain_text(value: str, max_length: int = 140) -> str:
    """Strip markup and control characters; templates still HTML-escape output."""
    cleaned = bleach.clean(value, tags=[], attributes={}, strip=True)
    return "".join(character for character in cleaned if character.isprintable())[
        :max_length
    ].strip()


def hash_token(token: str) -> str:
    """Hash a bearer token before persisting it in the session table."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_payment_pin(pin: str, salt: bytes | None = None) -> tuple[str, str]:
    """Store a payment PIN as a salted HMAC protected by the application secret."""
    salt_bytes = salt or secrets.token_bytes(16)
    key = current_app.config["SECRET_KEY"].encode("utf-8")
    digest = hmac.new(key, salt_bytes + pin.encode("ascii"), hashlib.sha256).hexdigest()
    return salt_bytes.hex(), digest


def verify_payment_pin(pin: str, salt_hex: str, expected_hex: str) -> bool:
    """Verify a payment PIN in constant time without exposing it to database-only leaks."""
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    _, actual = hash_payment_pin(pin, salt)
    return hmac.compare_digest(actual, expected_hex)
