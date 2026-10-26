"""Flask application for a secure, local-only online banking demonstration."""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from io import BytesIO
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps

import qrcode
import qrcode.image.svg
from PIL import Image, ImageOps, UnidentifiedImageError
from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    send_file,
    session,
    url_for,
)

from avl_tree import AVLTree
from audit_chain import append_audit_entry, verify_audit_chain
from config import Config
from database import connect, initialize_database, transaction
from graph_analyzer import AccessGraph
from mfa_security import (
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_code,
    provisioning_uri,
    valid_totp_counter,
)
from risk_engine import RiskEngine, RiskFeatures, distance_km
from security import (
    decrypt_sensitive_value,
    encrypt_sensitive_value,
    hash_password,
    hash_payment_pin,
    hash_token,
    is_bcrypt_password_hash,
    sanitize_plain_text,
    verify_password,
    verify_payment_pin,
)
from statement_pdf import generate_monthly_statement


app = Flask(__name__)
app.config.from_object(Config)
app.logger.setLevel(logging.INFO)
risk_engine = RiskEngine()
balance_index = AVLTree()
balance_index_lock = threading.RLock()

USERNAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,29}$")
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
NATIONAL_ID_PATTERN = re.compile(r"^[0-9]{6,20}$")
PHONE_PATTERN = re.compile(r"^[0-9]{7,15}$")
PASSWORD_PATTERN = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).{8,128}$"
)
PAYMENT_PIN_PATTERN = re.compile(r"^[0-9]{6}$")
DEVICE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,80}$")
IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,80}$")
REGISTRATION_OPENING_BALANCE_CENTS = 0


class TransferConflict(Exception):
    """Raised when a transfer idempotency key is reused with other details."""
with app.app_context():
    initialize_database()
    _DUMMY_SALT, _DUMMY_PASSWORD_HASH = hash_password(
        "non-matching-dummy-password-for-timing"
    )


def _now() -> int:
    return int(time.time())


@app.template_filter("datetime")
def format_datetime(timestamp: int) -> str:
    """Render a Unix timestamp in a compact, timezone-independent UTC format."""
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(timestamp))


@app.template_filter("month_year")
def format_month_year(timestamp: int) -> str:
    """Render an account creation timestamp as a compact membership date."""
    return time.strftime("%b %Y", time.gmtime(timestamp))


def _payload() -> dict[str, object]:
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return request.form.to_dict()


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_template_context() -> dict[str, object]:
    active_user = _active_user()
    return {
        "csrf_token": _csrf_token(),
        "current_username": active_user["username"] if active_user else None,
        "current_short_name": (
            active_user["full_name"].split()[0] if active_user else None
        ),
        "current_profile_image_url": (
            url_for("profile_image", filename=active_user["profile_image"])
            if active_user and active_user["profile_image"]
            else None
        ),
        "current_is_admin": bool(active_user and _is_admin(active_user)),
        "development_mode": app.config["DEVELOPMENT"],
    }


@app.after_request
def add_security_headers(response):
    """Apply baseline browser protections to pages and API responses."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; base-uri 'self'; connect-src 'self'; "
        "font-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
        "img-src 'self' data: blob:; object-src 'none'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = (
        "geolocation=(self), camera=(), microphone=()"
    )
    if app.config["SESSION_COOKIE_SECURE"] and request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


def _valid_csrf() -> bool:
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or _payload().get("csrf_token")
    return (
        isinstance(expected, str)
        and isinstance(supplied, str)
        and secrets.compare_digest(expected, supplied)
    )


def _require_csrf() -> tuple[dict[str, object], int] | None:
    if not _valid_csrf():
        return {"error": "The request token is invalid or expired. Reload and retry."}, 400
    return None


def _client_ip() -> str:
    # Do not trust X-Forwarded-For unless a trusted proxy is configured separately.
    return request.remote_addr or "unknown"


def _privacy_digest(value: str) -> str:
    """Key hashes of login identifiers so stored audit rows do not expose them."""
    return hmac.new(
        app.config["SECRET_KEY"].encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _throttle_key(username: str) -> str:
    """Return a username-scoped throttle key unaffected by client IP changes."""
    return _privacy_digest(f"username:{username.strip().casefold()}")


def _ip_throttle_key() -> str:
    """Return a network throttle key to limit attempts spread across usernames."""
    return _privacy_digest(f"ip:{_client_ip()}")


def _login_throttle_keys(username: str) -> tuple[str, str]:
    return _throttle_key(username), _ip_throttle_key()


def _record_login_attempt(
    username: str,
    user_id: int | None,
    device_hash: str | None,
    outcome: str,
    *,
    risk_level: str | None = None,
    risk_score: float | None = None,
) -> None:
    with transaction(immediate=True) as connection:
        connection.execute(
            """
            INSERT INTO login_attempts
                (user_id, username_hash, ip_hash, device_hash, outcome,
                 risk_level, risk_score, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                _privacy_digest(f"username:{username.strip().casefold()}"),
                _privacy_digest(f"ip:{_client_ip()}"),
                device_hash,
                outcome,
                risk_level,
                risk_score,
                _now(),
            ),
        )


def _device_hash(device_id: object) -> str | None:
    if not isinstance(device_id, str) or not DEVICE_PATTERN.fullmatch(device_id):
        return None
    return hash_token(device_id)


def _coordinates(data: dict[str, object]) -> tuple[float | None, float | None]:
    try:
        latitude = float(data["latitude"]) if data.get("latitude") not in (None, "") else None
        longitude = float(data["longitude"]) if data.get("longitude") not in (None, "") else None
    except (TypeError, ValueError):
        return None, None
    if latitude is None or longitude is None:
        return None, None
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return None, None
    return latitude, longitude


def _amount_cents(value: object) -> int | None:
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
        return None
    cents = int((amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    if cents > app.config["MAX_TRANSFER_CENTS"]:
        return None
    return cents


def _json_error(message: str, status: int) -> tuple[object, int]:
    return jsonify({"error": message}), status


def _active_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    token = session.get("session_token")
    if not isinstance(user_id, int) or not isinstance(token, str):
        return None
    connection = connect()
    try:
        rows = connection.execute(
            """
            SELECT u.id, u.full_name, u.username, u.email, u.account_number,
                   u.balance_cents, u.created_at, u.profile_image, u.can_transfer,
                   u.account_status, u.mfa_enabled, u.role, s.expires_at
            FROM sessions AS s
            JOIN users AS u ON u.id = s.user_id
            WHERE s.token_hash = ? AND s.user_id = ?
              AND s.revoked = 0 AND s.expires_at > ?
              AND u.account_status = 'active'
            """,
            (hash_token(token), user_id, _now()),
        ).fetchone()
    finally:
        connection.close()
    return rows


def _login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = _active_user()
        if user is None:
            session.clear()
            if request.path.startswith("/api/"):
                return _json_error("Your session has expired. Please sign in again.", 401)
            return redirect(url_for("auth_page"))
        if request.endpoint == "admin_dashboard":
            resource = "Admin" if _is_admin(user) else "Admin denied"
        elif request.endpoint == "profile_image":
            resource = "Files"
        elif request.endpoint == "transfer":
            resource = "Transfers"
        else:
            resource = "Database"
        _record_access_event(user["id"], resource)
        return view(user, *args, **kwargs)

    return wrapped


def _audit(user_id: int, event_type: str) -> None:
    now = _now()
    with transaction(immediate=True) as connection:
        connection.execute(
            "INSERT INTO audit_events (user_id, event_type, occurred_at) VALUES (?, ?, ?)",
            (user_id, event_type, now),
        )
        append_audit_entry(connection, user_id, event_type, {}, now)


def _audit_in_transaction(
    connection: sqlite3.Connection,
    user_id: int,
    operation: str,
    details: dict[str, object] | None = None,
    occurred_at: int | None = None,
) -> str:
    timestamp = _now() if occurred_at is None else occurred_at
    connection.execute(
        "INSERT INTO audit_events (user_id, event_type, occurred_at) VALUES (?, ?, ?)",
        (user_id, operation, timestamp),
    )
    return append_audit_entry(connection, user_id, operation, details or {}, timestamp)


def _consume_mfa_code(
    connection: sqlite3.Connection,
    user_id: int,
    code: str,
    now: int,
) -> tuple[bool, bool]:
    account = connection.execute(
        """
        SELECT mfa_secret_ciphertext, mfa_enabled, last_mfa_counter,
               mfa_failed_attempts, mfa_locked_until
        FROM users WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    if account is None or not account["mfa_enabled"] or not account["mfa_secret_ciphertext"]:
        return False, False
    if account["mfa_locked_until"] > now:
        return False, True

    try:
        normalized_code = code.strip().upper()
        secret = decrypt_sensitive_value(account["mfa_secret_ciphertext"])
        counter = valid_totp_counter(secret, normalized_code, now)
    except (TypeError, UnicodeEncodeError, ValueError):
        counter = None

    if counter is not None:
        if counter > account["last_mfa_counter"]:
            updated = connection.execute(
                """
                UPDATE users SET last_mfa_counter = ?,
                    mfa_failed_attempts = 0, mfa_locked_until = 0
                WHERE id = ? AND mfa_enabled = 1 AND last_mfa_counter < ?
                """,
                (counter, user_id, counter),
            )
            if updated.rowcount == 1:
                return True, False
    else:
        recovery_hash = hash_recovery_code(code)
        consumed = connection.execute(
            """
            UPDATE mfa_recovery_codes SET used_at = ?
            WHERE user_id = ? AND code_hash = ? AND used_at IS NULL
            """,
            (now, user_id, recovery_hash),
        )
        if consumed.rowcount == 1:
            connection.execute(
                """
                UPDATE users SET mfa_failed_attempts = 0, mfa_locked_until = 0
                WHERE id = ?
                """,
                (user_id,),
            )
            return True, False

    attempts = account["mfa_failed_attempts"] + 1
    locked_until = (
        now + app.config["MFA_LOCKOUT_SECONDS"]
        if attempts >= app.config["MFA_MAX_ATTEMPTS"]
        else 0
    )
    connection.execute(
        """
        UPDATE users SET mfa_failed_attempts = ?, mfa_locked_until = ?
        WHERE id = ?
        """,
        (attempts, locked_until, user_id),
    )
    return False, bool(locked_until)


def _record_access_event(user_id: int, resource: str) -> None:
    with transaction() as connection:
        connection.execute(
            "INSERT INTO access_events (user_id, resource, occurred_at) VALUES (?, ?, ?)",
            (user_id, resource, _now()),
        )


def _record_risk_event(
    user_id: int,
    event_type: str,
    assessment: dict[str, object],
) -> None:
    with transaction() as connection:
        connection.execute(
            """
            INSERT INTO risk_events
                (user_id, event_type, risk_level, risk_score, action, reasons_json,
                 features_json, occurred_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                event_type,
                assessment["level"],
                assessment["score"],
                assessment["action"],
                json.dumps(assessment["reasons"], separators=(",", ":")),
                json.dumps(assessment["features"], separators=(",", ":")),
                _now(),
            ),
        )


def _record_security_incident(
    user_id: int,
    event_type: str,
    assessment: dict[str, object],
) -> None:
    now = _now()
    with transaction(immediate=True) as connection:
        details = {
            "risk_score": assessment["score"],
            "reasons": assessment["reasons"],
            "features": assessment["features"],
        }
        audit_hash = _audit_in_transaction(
            connection,
            user_id,
            f"High-risk {event_type} blocked",
            details,
            now,
        )
        connection.execute(
            """
            INSERT INTO security_incidents
                (user_id, event_type, risk_score, details_json, occurred_at,
                 audit_entry_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                event_type,
                assessment["score"],
                json.dumps(details, sort_keys=True, separators=(",", ":")),
                now,
                audit_hash,
            ),
        )


def _risk_gate(event_type: str):
    """Block high-risk actions and append a signed incident to the audit chain."""
    def decorate(view):
        @wraps(view)
        def wrapped(assessment, user_id: int, *args, **kwargs):
            score = float(assessment["score"])
            if score > 0.75:
                _record_security_incident(user_id, event_type, assessment)
                return False
            return view(assessment, user_id, *args, **kwargs)

        return wrapped

    return decorate


@_risk_gate("login")
def _risk_allows_login(assessment: dict[str, object], user_id: int) -> bool:
    return True


@_risk_gate("transfer")
def _risk_allows_transfer(assessment: dict[str, object], user_id: int) -> bool:
    return True


def _record_login(
    user_id: int,
    username: str,
    device_hash: str,
    latitude: float | None,
    longitude: float | None,
    risk_level: str,
    risk_score: float,
) -> None:
    now = _now()
    with transaction(immediate=True) as connection:
        connection.execute(
            """
            INSERT INTO known_devices (user_id, device_hash, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, device_hash)
            DO UPDATE SET last_seen_at = excluded.last_seen_at
            """,
            (user_id, device_hash, now, now),
        )
        connection.execute(
            """
            INSERT INTO login_events (user_id, occurred_at, latitude, longitude)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, now, latitude, longitude),
        )
        _audit_in_transaction(connection, user_id, "Login", {}, now)
        connection.executemany(
            "INSERT INTO access_events (user_id, resource, occurred_at) VALUES (?, ?, ?)",
            ((user_id, "Login", now), (user_id, "Database", now)),
        )
        connection.execute(
            """
            INSERT INTO login_attempts
                (user_id, username_hash, ip_hash, device_hash, outcome,
                 risk_level, risk_score, occurred_at)
            VALUES (?, ?, ?, ?, 'success', ?, ?, ?)
            """,
            (
                user_id,
                _privacy_digest(f"username:{username.strip().casefold()}"),
                _privacy_digest(f"ip:{_client_ip()}"),
                device_hash,
                risk_level,
                risk_score,
                now,
            ),
        )


def _create_session(user: sqlite3.Row) -> None:
    token = secrets.token_urlsafe(32)
    expires_at = _now() + int(app.config["PERMANENT_SESSION_LIFETIME"].total_seconds())
    with transaction(immediate=True) as connection:
        connection.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (hash_token(token), user["id"], expires_at),
        )
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["session_token"] = token
    _csrf_token()


def _create_login_challenge(
    user_id: int,
    device_hash: str,
    latitude: float | None,
    longitude: float | None,
    verification_method: str,
    risk_level: str,
    risk_score: float,
) -> str:
    challenge_id = secrets.token_urlsafe(32)
    now = _now()
    with transaction(immediate=True) as connection:
        connection.execute(
            "DELETE FROM login_challenges WHERE expires_at <= ?",
            (now,),
        )
        connection.execute(
            "DELETE FROM login_challenges WHERE user_id = ?",
            (user_id,),
        )
        connection.execute(
            """
            INSERT INTO login_challenges
                (challenge_hash, user_id, device_hash, latitude, longitude,
                 verification_method, risk_level, risk_score, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hash_token(challenge_id),
                user_id,
                device_hash,
                latitude,
                longitude,
                verification_method,
                risk_level,
                risk_score,
                now + app.config["LOGIN_CHALLENGE_SECONDS"],
                now,
            ),
        )
    return challenge_id


def _verify_user_payment_pin(
    user_id: int, payment_pin: str
) -> tuple[bool, bool]:
    """Verify a PIN and persist account-level lockout after repeated failures."""
    now = _now()
    with transaction(immediate=True) as connection:
        user = connection.execute(
            """
            SELECT payment_pin_salt, payment_pin_hash, failed_pin_attempts,
                   pin_locked_until
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        if user is None:
            return False, False
        if user["pin_locked_until"] > now:
            return False, True
        if not user["payment_pin_salt"] or not user["payment_pin_hash"]:
            return False, False
        if verify_payment_pin(
            payment_pin, user["payment_pin_salt"], user["payment_pin_hash"]
        ):
            connection.execute(
                """
                UPDATE users SET failed_pin_attempts = 0, pin_locked_until = 0
                WHERE id = ?
                """,
                (user_id,),
            )
            return True, False
        attempts = user["failed_pin_attempts"] + 1
        locked_until = (
            now + app.config["PAYMENT_PIN_LOCKOUT_SECONDS"]
            if attempts >= app.config["PAYMENT_PIN_MAX_ATTEMPTS"]
            else 0
        )
        connection.execute(
            """
            UPDATE users SET failed_pin_attempts = ?, pin_locked_until = ?
            WHERE id = ?
            """,
            (attempts, locked_until, user_id),
        )
        return False, bool(locked_until)


def _record_failed_login(
    connection: sqlite3.Connection,
    user_id: int | None,
    throttle_keys: tuple[str, str],
    now: int,
    username: str,
    device_hash: str | None,
) -> bool:
    if user_id is not None:
        connection.execute(
            """
            UPDATE users SET
                failed_login_attempts = failed_login_attempts + 1,
                account_status = CASE
                    WHEN failed_login_attempts + 1 >= ? THEN 'locked'
                    ELSE account_status
                END,
                account_locked_at = CASE
                    WHEN failed_login_attempts + 1 >= ? THEN ?
                    ELSE account_locked_at
                END
            WHERE id = ? AND account_status = 'active'
            """,
            (
                app.config["LOGIN_LOCKOUT_ATTEMPTS"],
                app.config["LOGIN_LOCKOUT_ATTEMPTS"],
                now,
                user_id,
            ),
        )
        status = connection.execute(
            "SELECT account_status FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        is_locked = status is None or status["account_status"] == "locked"
        _audit_in_transaction(
            connection,
            user_id,
            "Account locked after failed logins" if is_locked else "Failed login attempt",
            {"account_locked": is_locked},
            now,
        )
        if is_locked:
            connection.execute(
                "UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user_id,)
            )
    locked_until = now + app.config["LOGIN_LOCKOUT_SECONDS"]
    for throttle_key in throttle_keys:
        connection.execute(
            """
            INSERT INTO auth_throttles
                (throttle_key, failed_attempts, locked_until, updated_at)
            VALUES (?, 1, 0, ?)
            ON CONFLICT(throttle_key) DO UPDATE SET
                failed_attempts = CASE
                    WHEN auth_throttles.locked_until > ?
                    THEN auth_throttles.failed_attempts
                    ELSE auth_throttles.failed_attempts + 1
                END,
                locked_until = CASE
                    WHEN auth_throttles.locked_until > ?
                    THEN auth_throttles.locked_until
                    WHEN auth_throttles.failed_attempts + 1 >= ? THEN ?
                    ELSE 0
                END,
                updated_at = excluded.updated_at
            """,
            (
                throttle_key,
                now,
                now,
                now,
                app.config["LOGIN_LOCKOUT_ATTEMPTS"],
                locked_until,
            ),
        )
    if user_id is None:
        return False
    is_locked = status is None or status["account_status"] == "locked"
    connection.execute(
        """
        INSERT INTO login_attempts
            (user_id, username_hash, ip_hash, device_hash, outcome, occurred_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            _privacy_digest(f"username:{username.strip().casefold()}"),
            _privacy_digest(f"ip:{_client_ip()}"),
            device_hash,
            "account_locked" if is_locked else "invalid_credentials",
            now,
        ),
    )
    return is_locked


def _risk_features_for_login(
    user_id: int,
    device_hash: str,
    latitude: float | None,
    longitude: float | None,
) -> RiskFeatures:
    connection = connect()
    try:
        known = connection.execute(
            "SELECT 1 FROM known_devices WHERE user_id = ? AND device_hash = ?",
            (user_id, device_hash),
        ).fetchone()
        previous = connection.execute(
            """
            SELECT occurred_at, latitude, longitude
            FROM login_events WHERE user_id = ?
            ORDER BY occurred_at DESC LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        recent_count = connection.execute(
            "SELECT COUNT(*) AS n FROM login_events WHERE user_id = ? AND occurred_at > ?",
            (
                user_id,
                _now() - app.config["LOGIN_VELOCITY_WINDOW_SECONDS"],
            ),
        ).fetchone()["n"]
    finally:
        connection.close()

    distance = 0.0
    interval = 0.0
    speed = 0.0
    if previous:
        interval = max(0.0, (_now() - previous["occurred_at"]) / 3600)
        distance = distance_km(
            previous["latitude"],
            previous["longitude"],
            latitude,
            longitude,
        )
        if interval > 0:
            speed = distance / interval
    return RiskFeatures(
        distance_km=distance,
        interval_hours=interval,
        physical_speed_kmh=speed,
        new_device=int(known is None),
        login_velocity=float(recent_count + 1),
    )


def _recipient(connection: sqlite3.Connection, destination: str) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT id, username, account_number
        FROM users
        WHERE username = ? COLLATE NOCASE OR account_number = ?
        """,
        (destination, destination),
    ).fetchone()


def _transfer_reference(row: sqlite3.Row) -> str:
    """Decrypt a transfer note while retaining read compatibility with old rows."""
    ciphertext = row["reference_ciphertext"]
    if ciphertext is not None:
        return decrypt_sensitive_value(ciphertext)
    return row["reference"]


def _execute_transfer(user_id: int, payload: dict[str, object]) -> dict[str, object]:
    destination = str(payload.get("recipient", "")).strip()
    reference = sanitize_plain_text(str(payload.get("reference", "")), 140)
    amount_cents = _amount_cents(payload.get("amount"))
    idempotency_key = str(payload.get("idempotency_key", "")).strip()
    if not destination or len(destination) > 30 or amount_cents is None:
        raise ValueError("Enter a valid recipient and an amount with at most two decimals.")
    if not IDEMPOTENCY_PATTERN.fullmatch(idempotency_key):
        raise ValueError("A valid transfer request key is required. Reload and retry.")

    now = _now()
    with transaction(immediate=True) as connection:
        sender = connection.execute(
            """
            SELECT id, username, full_name, account_number, balance_cents, can_transfer
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
        recipient = _recipient(connection, destination)
        recipient_profile = connection.execute(
            "SELECT full_name, account_number FROM users WHERE id = ?",
            (recipient["id"],),
        ).fetchone() if recipient is not None else None
        if sender is None:
            raise LookupError("The signed-in account no longer exists.")
        if recipient is None:
            raise LookupError("The recipient was not found.")
        if recipient["id"] == sender["id"]:
            raise ValueError("Transfers to the same account are not allowed.")
        if not sender["can_transfer"]:
            raise PermissionError(
                "Transfers are disabled for this account. Contact the administrator."
            )
        previous = connection.execute(
            """
            SELECT id, recipient_id, amount_cents, reference,
                   reference_ciphertext, receipt_reference
            FROM transfers WHERE sender_id = ? AND idempotency_key = ?
            """,
            (user_id, idempotency_key),
        ).fetchone()
        if previous is not None:
            if (
                previous["recipient_id"] != recipient["id"]
                or previous["amount_cents"] != amount_cents
                or _transfer_reference(previous) != reference
            ):
                raise TransferConflict(
                    "This request key was already used for a different transfer."
                )
            transfer_id = previous["id"]
            receipt_reference = previous["receipt_reference"]
            new_sender_balance = sender["balance_cents"]
        else:
            debit = connection.execute(
                """
                UPDATE users SET balance_cents = balance_cents - ?
                WHERE id = ? AND balance_cents >= ?
                """,
                (amount_cents, user_id, amount_cents),
            )
            if debit.rowcount != 1:
                raise ValueError("Insufficient available balance.")
            credit = connection.execute(
                "UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                (amount_cents, recipient["id"]),
            )
            if credit.rowcount != 1:
                raise LookupError("The recipient account is no longer available.")
            cursor = connection.execute(
                """
                INSERT INTO transfers
                    (sender_id, recipient_id, amount_cents, reference,
                     reference_ciphertext,
                     receipt_reference, idempotency_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    recipient["id"],
                    amount_cents,
                    "",
                    encrypt_sensitive_value(reference),
                    secrets.token_urlsafe(18),
                    idempotency_key,
                    now,
                ),
            )
            transfer_id = cursor.lastrowid
            receipt_reference = connection.execute(
                "SELECT receipt_reference FROM transfers WHERE id = ?", (transfer_id,)
            ).fetchone()["receipt_reference"]
            connection.executemany(
                """
                INSERT INTO ledger_entries
                    (transfer_id, user_id, direction, amount_cents, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    (transfer_id, user_id, "debit", amount_cents, now),
                    (transfer_id, recipient["id"], "credit", amount_cents, now),
                ),
            )
            _audit_in_transaction(
                connection,
                user_id,
                "Transfer",
                {
                    "transfer_id": transfer_id,
                    "amount_cents": amount_cents,
                    "recipient_user_id": recipient["id"],
                },
                now,
            )
            new_sender_balance = sender["balance_cents"] - amount_cents
        new_recipient = connection.execute(
            "SELECT balance_cents FROM users WHERE id = ?", (recipient["id"],)
        ).fetchone()

    with balance_index_lock:
        balance_index.insert(user_id, new_sender_balance)
        balance_index.insert(recipient["id"], new_recipient["balance_cents"])
    return {
        "message": "Transfer completed successfully.",
        "transfer_id": transfer_id,
        "amount": f"{amount_cents / 100:.2f}",
        "recipient": recipient["username"],
        "balance": f"{new_sender_balance / 100:.2f}",
        "receipt_id": receipt_reference,
        "created_at": now,
        "sender_name": sender["full_name"],
        "sender_account": sender["account_number"],
        "recipient_name": recipient_profile["full_name"],
        "recipient_account": recipient_profile["account_number"],
        "fee": "0.00",
    }


def _transfer_risk(user_id: int, amount_cents: int) -> dict[str, object]:
    connection = connect()
    try:
        user = connection.execute(
            "SELECT opening_balance_cents FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        average = connection.execute(
            "SELECT AVG(amount_cents) AS average FROM transfers WHERE sender_id = ?",
            (user_id,),
        ).fetchone()["average"]
        setting = connection.execute(
            "SELECT setting_value FROM app_settings "
            "WHERE setting_key = 'transfer_risk_ratio_limit'"
        ).fetchone()
    finally:
        connection.close()
    if user is None or setting is None:
        raise RuntimeError("Transfer risk settings or account data are unavailable.")
    baseline = average or user["opening_balance_cents"] or 10_000
    assessment = risk_engine.assess(
        RiskFeatures(
            amount_ratio=amount_cents / baseline,
        ),
        amount_ratio_limit=setting["setting_value"],
    )
    _record_risk_event(user_id, "transfer", assessment)
    return assessment


def _is_admin(user: sqlite3.Row) -> bool:
    admin_username = app.config["ADMIN_USERNAME"].casefold()
    return bool(
        admin_username
        and user["role"] == "admin"
        and user["username"].casefold() == admin_username
    )


def _transfer_risk_ratio_limit() -> int:
    connection = connect()
    try:
        setting = connection.execute(
            "SELECT setting_value FROM app_settings "
            "WHERE setting_key = 'transfer_risk_ratio_limit'"
        ).fetchone()
    finally:
        connection.close()
    if setting is None:
        raise RuntimeError("The transfer risk threshold setting is unavailable.")
    return setting["setting_value"]


def _monitor_data(user_id: int) -> dict[str, object]:
    connection = connect()
    try:
        events = connection.execute(
            """
            SELECT resource FROM (
                SELECT resource, occurred_at, id FROM access_events
                WHERE user_id = ? ORDER BY occurred_at DESC, id DESC LIMIT 500
            ) ORDER BY occurred_at ASC, id ASC
            """,
            (user_id,),
        ).fetchall()
        users = connection.execute(
            "SELECT id, balance_cents FROM users ORDER BY id"
        ).fetchall()
    finally:
        connection.close()
    graph = AccessGraph.from_sequence(row["resource"] for row in events)
    with balance_index_lock:
        for row in users:
            balance_index.insert(row["id"], row["balance_cents"])
        avl = {
            "account_count": balance_index.size,
            "height": balance_index.height,
            "shape": balance_index.shape(),
        }
    return {
        "graph": graph.summary(),
        "avl": avl,
        "risk_controls": [
            "Three consecutive incorrect login passwords lock the account until admin unlock.",
            "Low-risk sign-in uses the login password; medium-risk sign-in requires a one-time Payment Password step-up.",
            "Unusually large transfers are flagged; Payment Password and balance checks still apply.",
            "Protected routes verify database-backed sessions and record access paths for graph scans.",
            "A synchronized AVL tree indexes account balances alongside SQLite.",
        ],
    }


def _admin_access_scans() -> list[dict[str, object]]:
    connection = connect()
    try:
        rows = connection.execute(
            """
            SELECT user_id, username, resource, occurred_at, id
            FROM (
                SELECT e.user_id, u.username, e.resource, e.occurred_at, e.id,
                       ROW_NUMBER() OVER (
                           PARTITION BY e.user_id
                           ORDER BY e.occurred_at DESC, e.id DESC
                       ) AS event_rank
                FROM access_events AS e
                JOIN users AS u ON u.id = e.user_id
            )
            WHERE event_rank <= 500
            ORDER BY user_id, occurred_at, id
            """
        ).fetchall()
    finally:
        connection.close()

    grouped: dict[int, dict[str, object]] = {}
    for row in rows:
        item = grouped.setdefault(
            row["user_id"],
            {"username": row["username"], "resources": []},
        )
        item["resources"].append(row["resource"])

    scans: list[dict[str, object]] = []
    for item in grouped.values():
        graph = AccessGraph.from_sequence(item["resources"])
        summary = graph.summary()
        scans.append(
            {
                "username": item["username"],
                "bfs": summary["bfs"],
                "dfs": summary["dfs"],
                "suspicious_paths": summary["suspicious_paths"],
            }
        )
    return sorted(scans, key=lambda item: str(item["username"]).casefold())


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/privacy")
def privacy_policy():
    return render_template("legal.html", legal_page="privacy")


@app.get("/terms")
def terms_of_service():
    return render_template("legal.html", legal_page="terms")


@app.get("/auth")
def auth_page():
    """Keep the original authentication URL as a sign-in compatibility route."""
    return redirect(url_for("login_page"))


@app.get("/login")
def login_page():
    user = _active_user()
    if user is not None:
        return redirect(
            url_for("admin_dashboard" if _is_admin(user) else "dashboard")
        )
    return render_template("auth.html", auth_mode="login")


@app.get("/register")
def register_page():
    user = _active_user()
    if user is not None:
        return redirect(
            url_for("admin_dashboard" if _is_admin(user) else "dashboard")
        )
    return render_template("auth.html", auth_mode="register")


def _ledger_entries(user_id: int, limit: int, offset: int = 0):
    """Fetch only the signed-in user's ledger rows using bound query parameters."""
    connection = connect()
    try:
        rows = connection.execute(
            """
            SELECT l.direction, l.amount_cents, l.created_at, t.reference,
                   t.reference_ciphertext,
                   CASE WHEN l.user_id = t.sender_id THEN receiver.username
                        ELSE sender.username END AS counterparty
            FROM ledger_entries AS l
            JOIN transfers AS t ON t.id = l.transfer_id
            JOIN users AS sender ON sender.id = t.sender_id
            JOIN users AS receiver ON receiver.id = t.recipient_id
            WHERE l.user_id = ?
            ORDER BY l.created_at DESC, l.id DESC
            LIMIT ? OFFSET ?
            """,
            (user_id, limit, offset),
        ).fetchall()
        return [
            {**dict(row), "reference": _transfer_reference(row)}
            for row in rows
        ]
    finally:
        connection.close()


@app.get("/dashboard")
@_login_required
def dashboard(user):
    entries = _ledger_entries(user["id"], 30)
    current_time = time.gmtime(_now())
    return render_template(
        "dashboard.html",
        user=user,
        entries=entries,
        statement_month=time.strftime("%Y-%m", current_time),
    )


@app.get("/transactions")
@_login_required
def transaction_history(user):
    page_size = 50
    requested_page = request.args.get("page", "1")
    if (
        not requested_page.isascii()
        or not requested_page.isdecimal()
        or len(requested_page) > 18
    ):
        abort(400, description="Page must be a positive integer.")
    requested_page_number = int(requested_page)
    if requested_page_number < 1:
        abort(400, description="Page must be a positive integer.")

    connection = connect()
    try:
        total_entries = connection.execute(
            "SELECT COUNT(*) AS count FROM ledger_entries WHERE user_id = ?",
            (user["id"],),
        ).fetchone()["count"]
    finally:
        connection.close()

    total_pages = max(1, (total_entries + page_size - 1) // page_size)
    page = min(requested_page_number, total_pages)
    entries = _ledger_entries(user["id"], page_size, (page - 1) * page_size)
    current_time = time.gmtime(_now())
    return render_template(
        "transaction_history.html",
        user=user,
        entries=entries,
        page=page,
        total_pages=total_pages,
        total_entries=total_entries,
        statement_month=time.strftime("%Y-%m", current_time),
    )


@app.get("/statements/monthly")
@_login_required
def monthly_statement(user):
    period = request.args.get("month", "")
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", period):
        return _json_error("Choose a valid statement month in YYYY-MM format.", 400)
    year, month = map(int, period.split("-"))
    current = time.gmtime(_now())
    if year < 1970 or (year, month) > (current.tm_year, current.tm_mon):
        return _json_error("Choose a valid statement month.", 400)
    connection = connect()
    try:
        pdf, verification_hash = generate_monthly_statement(
            connection,
            user["id"],
            year,
            month,
            app.config["SECRET_KEY"],
        )
    finally:
        connection.close()
    response = send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"finbest-statement-{year}-{month:02d}.pdf",
        max_age=0,
    )
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Statement-HMAC-SHA256"] = verification_hash
    return response


@app.get("/profile")
@_login_required
def profile_page(user):
    connection = connect()
    try:
        profile = connection.execute(
            """
            SELECT full_name, username, email, phone, account_number, created_at,
                   profile_image, mfa_enabled
            FROM users WHERE id = ?
            """,
            (user["id"],),
        ).fetchone()
    finally:
        connection.close()
    if profile is None:
        abort(404)
    return render_template(
        "profile.html",
        user=profile,
        profile_image_url=(
            url_for("profile_image", filename=profile["profile_image"])
            if profile["profile_image"]
            else None
        ),
    )


@app.get("/profile-images/<filename>")
@_login_required
def profile_image(user, filename):
    if not re.fullmatch(r"[a-f0-9]{48}\.(?:png|jpg|webp)", filename):
        abort(404)
    connection = connect()
    try:
        found = connection.execute(
            "SELECT 1 FROM users WHERE id = ? AND profile_image = ?",
            (user["id"], filename),
        ).fetchone()
    finally:
        connection.close()
    if found is None:
        abort(404)
    response = send_from_directory(app.config["PROFILE_IMAGE_DIR"], filename)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, max-age=300"
    return response


@app.post("/api/profile/phone")
@_login_required
def update_profile_phone(user):
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    phone = str(_payload().get("phone", "")).strip()
    if not PHONE_PATTERN.fullmatch(phone):
        return _json_error("Phone number must contain 7 to 15 digits.", 400)
    with transaction(immediate=True) as connection:
        connection.execute("UPDATE users SET phone = ? WHERE id = ?", (phone, user["id"]))
        _audit_in_transaction(
            connection,
            user["id"],
            "Profile updated",
            {"field": "phone"},
        )
    return jsonify({"message": "Phone number updated.", "phone": phone})


@app.post("/api/profile/password")
@_login_required
def update_profile_password(user):
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    data = _payload()
    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))
    connection = connect()
    try:
        credentials = connection.execute(
            "SELECT password_salt, password_hash FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
    finally:
        connection.close()
    if credentials is None or not verify_password(
        current_password, credentials["password_salt"], credentials["password_hash"]
    ):
        return _json_error("Current password is incorrect.", 401)
    if not PASSWORD_PATTERN.fullmatch(new_password):
        return _json_error(
            "New password must be 8 to 128 characters and include uppercase, lowercase, "
            "a number, and a symbol.",
            400,
        )
    salt, digest = hash_password(new_password)
    with transaction(immediate=True) as connection:
        connection.execute(
            "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = ?",
            (salt, digest, user["id"]),
        )
        connection.execute(
            """
            UPDATE sessions SET revoked = 1
            WHERE user_id = ? AND token_hash != ?
            """,
            (user["id"], hash_token(session["session_token"])),
        )
        _audit_in_transaction(
            connection,
            user["id"],
            "Password changed",
            {},
        )
    return jsonify({"message": "Login password updated."})


@app.post("/api/mfa/setup")
@_login_required
def setup_mfa(user):
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    if user["mfa_enabled"]:
        return _json_error("Authenticator MFA is already enabled.", 409)

    secret = generate_totp_secret()
    with transaction(immediate=True) as connection:
        mfa_lock = connection.execute(
            "SELECT mfa_locked_until FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
        if mfa_lock is None:
            return _json_error("The account was not found.", 404)
        if mfa_lock["mfa_locked_until"] > _now():
            return _json_error("Authenticator setup is temporarily locked.", 423)
        connection.execute(
            """
            UPDATE users SET mfa_pending_secret_ciphertext = ?
            WHERE id = ? AND mfa_enabled = 0
            """,
            (encrypt_sensitive_value(secret), user["id"]),
        )
    qr_buffer = BytesIO()
    qrcode.make(provisioning_uri(secret, user["email"])).save(qr_buffer, format="PNG")
    response = jsonify(
        {
            "secret": secret,
            "qr_code": "data:image/png;base64,"
            + base64.b64encode(qr_buffer.getvalue()).decode("ascii"),
            "message": "Scan the QR code, then enter the current authenticator code to enable MFA.",
        }
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/mfa/enable")
@_login_required
def enable_mfa(user):
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    code = str(_payload().get("totp_code", "")).strip()
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return _json_error("Enter the six-digit code from your authenticator app.", 400)

    now = _now()
    recovery_codes = generate_recovery_codes(
        app.config["MFA_RECOVERY_CODE_COUNT"]
    )
    with transaction(immediate=True) as connection:
        account = connection.execute(
            """
            SELECT mfa_pending_secret_ciphertext, mfa_enabled,
                   mfa_failed_attempts, mfa_locked_until
            FROM users WHERE id = ?
            """,
            (user["id"],),
        ).fetchone()
        if account is None:
            return _json_error("The account was not found.", 404)
        if account["mfa_enabled"]:
            return _json_error("Authenticator MFA is already enabled.", 409)
        if account["mfa_locked_until"] > now:
            return _json_error("Authenticator setup is temporarily locked.", 423)
        if not account["mfa_pending_secret_ciphertext"]:
            return _json_error("Start MFA setup before confirming a code.", 409)
        secret = decrypt_sensitive_value(account["mfa_pending_secret_ciphertext"])
        counter = valid_totp_counter(secret, code, now)
        if counter is None:
            attempts = account["mfa_failed_attempts"] + 1
            locked_until = (
                now + app.config["MFA_LOCKOUT_SECONDS"]
                if attempts >= app.config["MFA_MAX_ATTEMPTS"]
                else 0
            )
            connection.execute(
                "UPDATE users SET mfa_failed_attempts = ?, mfa_locked_until = ? "
                "WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            return _json_error("The authenticator code is invalid or expired.", 401)
        connection.execute(
            """
            UPDATE users SET mfa_secret_ciphertext = mfa_pending_secret_ciphertext,
                mfa_pending_secret_ciphertext = NULL, mfa_enabled = 1,
                last_mfa_counter = ?, mfa_failed_attempts = 0, mfa_locked_until = 0
            WHERE id = ?
            """,
            (counter, user["id"]),
        )
        connection.execute(
            "DELETE FROM mfa_recovery_codes WHERE user_id = ?",
            (user["id"],),
        )
        connection.executemany(
            """
            INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at)
            VALUES (?, ?, ?)
            """,
            [
                (user["id"], hash_recovery_code(recovery_code), now)
                for recovery_code in recovery_codes
            ],
        )
        _audit_in_transaction(
            connection,
            user["id"],
            "Authenticator MFA enabled",
            {"recovery_code_count": len(recovery_codes)},
            now,
        )

    response = jsonify(
        {
            "message": "Authenticator MFA enabled. Save each recovery code securely; they are shown only once.",
            "recovery_codes": recovery_codes,
        }
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/mfa/disable")
@_login_required
def disable_mfa(user):
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    data = _payload()
    password = str(data.get("password", ""))
    code = str(data.get("totp_code", "")).strip()
    connection = connect()
    try:
        credentials = connection.execute(
            "SELECT password_salt, password_hash FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
    finally:
        connection.close()
    if credentials is None or not verify_password(
        password, credentials["password_salt"], credentials["password_hash"]
    ):
        return _json_error("Current password is incorrect.", 401)

    now = _now()
    with transaction(immediate=True) as connection:
        valid, locked = _consume_mfa_code(connection, user["id"], code, now)
        if locked:
            return _json_error("MFA is temporarily locked after repeated failures.", 423)
        if not valid:
            return _json_error("Enter a valid, unused authenticator code or recovery code.", 401)
        connection.execute(
            """
            UPDATE users SET mfa_secret_ciphertext = NULL,
                mfa_pending_secret_ciphertext = NULL, mfa_enabled = 0,
                last_mfa_counter = -1, mfa_failed_attempts = 0, mfa_locked_until = 0
            WHERE id = ?
            """,
            (user["id"],),
        )
        connection.execute(
            "DELETE FROM mfa_recovery_codes WHERE user_id = ?",
            (user["id"],),
        )
        _audit_in_transaction(
            connection,
            user["id"],
            "Authenticator MFA disabled",
            {},
            now,
        )
    return jsonify({"message": "Authenticator MFA has been disabled."})


@app.post("/api/profile/photo")
@_login_required
def update_profile_photo(user):
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    upload = request.files.get("photo")
    if upload is None or not upload.filename:
        return _json_error("Choose a profile image to upload.", 400)
    if request.content_length and request.content_length > (
        app.config["MAX_PROFILE_IMAGE_BYTES"] + 64 * 1024
    ):
        return _json_error("Profile images must be 2 MB or smaller.", 413)
    content = upload.stream.read(app.config["MAX_PROFILE_IMAGE_BYTES"] + 1)
    if not content or len(content) > app.config["MAX_PROFILE_IMAGE_BYTES"]:
        return _json_error("Profile images must be between 1 byte and 2 MB.", 413)
    try:
        with Image.open(BytesIO(content)) as uploaded_image:
            if uploaded_image.format not in ("PNG", "JPEG", "WEBP"):
                return _json_error("Choose a valid PNG, JPEG, or WebP image.", 400)
            if uploaded_image.width * uploaded_image.height > 10_000_000:
                return _json_error("Profile images must be 10 megapixels or smaller.", 400)
            image_format = uploaded_image.format
            uploaded_image.verify()
        with Image.open(BytesIO(content)) as uploaded_image:
            image = ImageOps.exif_transpose(uploaded_image)
            image.thumbnail((512, 512))
            if image_format == "JPEG" and image.mode not in ("RGB", "L"):
                image = image.convert("RGB")
            output = BytesIO()
            image.save(output, format=image_format, optimize=True)
            content = output.getvalue()
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        return _json_error("The selected image could not be decoded.", 400)
    extension = {"PNG": "png", "JPEG": "jpg", "WEBP": "webp"}[image_format]
    filename = f"{secrets.token_hex(24)}.{extension}"
    os.makedirs(app.config["PROFILE_IMAGE_DIR"], mode=0o700, exist_ok=True)
    destination = os.path.join(app.config["PROFILE_IMAGE_DIR"], filename)
    with open(destination, "xb") as image_file:
        image_file.write(content)
    with transaction(immediate=True) as connection:
        old_image = connection.execute(
            "SELECT profile_image FROM users WHERE id = ?", (user["id"],)
        ).fetchone()["profile_image"]
        connection.execute(
            "UPDATE users SET profile_image = ? WHERE id = ?",
            (filename, user["id"]),
        )
        _audit_in_transaction(
            connection,
            user["id"],
            "Profile picture changed",
            {},
        )
    if old_image and re.fullmatch(r"[a-f0-9]{48}\.(?:png|jpg|webp)", old_image):
        old_path = os.path.join(app.config["PROFILE_IMAGE_DIR"], old_image)
        if os.path.isfile(old_path):
            os.remove(old_path)
    return jsonify(
        {
            "message": "Profile picture updated.",
            "image_url": url_for("profile_image", filename=filename),
        }
    )


@app.get("/risk-monitor")
@_login_required
def risk_monitor(user):
    return render_template("risk_monitor.html", user=user)


@app.get("/admin/settings")
@app.get("/admin/dashboard")
@_login_required
def admin_dashboard(user):
    if not _is_admin(user):
        abort(403)
    connection = connect()
    try:
        locked_accounts = connection.execute(
            """
            SELECT id, full_name, username, account_number,
                   failed_login_attempts, account_locked_at
            FROM users WHERE account_status = 'locked'
            ORDER BY account_locked_at, id
            """
        ).fetchall()
        customers = connection.execute(
            """
            SELECT id, full_name, username, account_number, can_transfer,
                   account_status
            FROM users WHERE id != ?
            ORDER BY username COLLATE NOCASE
            """,
            (user["id"],),
        ).fetchall()
        transfers = connection.execute(
            """
            SELECT t.id, t.amount_cents, t.reference, t.reference_ciphertext,
                   t.created_at,
                   sender.username AS sender_username,
                   sender.account_number AS sender_account,
                   recipient.username AS recipient_username,
                   recipient.account_number AS recipient_account
            FROM transfers AS t
            JOIN users AS sender ON sender.id = t.sender_id
            JOIN users AS recipient ON recipient.id = t.recipient_id
            ORDER BY t.created_at DESC, t.id DESC
            """
        ).fetchall()
        risk_events = connection.execute(
            """
            SELECT r.id, r.event_type, r.risk_level, r.risk_score, r.action, r.reasons_json,
                   r.features_json, r.occurred_at, u.username
            FROM risk_events AS r
            JOIN users AS u ON u.id = r.user_id
            ORDER BY r.occurred_at DESC, r.id DESC LIMIT 100
            """
        ).fetchall()
        activity_events = connection.execute(
            """
            SELECT a.event_type, a.occurred_at, u.username
            FROM audit_events AS a
            JOIN users AS u ON u.id = a.user_id
            ORDER BY a.occurred_at DESC, a.id DESC LIMIT 100
            """
        ).fetchall()
        incidents = connection.execute(
            """
            SELECT i.id, i.event_type, i.risk_score, i.details_json,
                   i.occurred_at, i.audit_entry_hash, u.username
            FROM security_incidents AS i
            JOIN users AS u ON u.id = i.user_id
            ORDER BY i.occurred_at DESC, i.id DESC LIMIT 100
            """
        ).fetchall()
        login_attempts = connection.execute(
            """
            SELECT a.occurred_at, a.outcome, a.risk_level, a.risk_score,
                   substr(a.ip_hash, 1, 12) AS ip_fingerprint,
                   substr(a.device_hash, 1, 12) AS device_fingerprint,
                   COALESCE(u.username, 'Unknown account') AS username
            FROM login_attempts AS a
            LEFT JOIN users AS u ON u.id = a.user_id
            ORDER BY a.occurred_at DESC, a.id DESC
            LIMIT 100
            """
        ).fetchall()
        audit_integrity = verify_audit_chain(connection)
    finally:
        connection.close()
    transfers = [
        {**dict(transfer), "reference": _transfer_reference(transfer)}
        for transfer in transfers
    ]
    risk_event_rows = [
        {
            **dict(event),
            "reasons": json.loads(event["reasons_json"]),
            "features": json.loads(event["features_json"]),
        }
        for event in risk_events
    ]
    return render_template(
        "admin_settings.html",
        user=user,
        transfer_risk_ratio_limit=_transfer_risk_ratio_limit(),
        locked_accounts=locked_accounts,
        customers=customers,
        transfers=transfers,
        risk_events=risk_event_rows,
        activity_events=activity_events,
        access_scans=_admin_access_scans(),
        incidents=incidents,
        login_attempts=login_attempts,
        audit_integrity=audit_integrity,
    )


@app.get("/api/admin/audit-chain/verify")
@_login_required
def verify_audit_chain_route(user):
    if not _is_admin(user):
        return _json_error("Admin access is required.", 403)
    connection = connect()
    try:
        result = verify_audit_chain(connection)
    finally:
        connection.close()
    return jsonify(result)


@app.post("/api/admin/transfer-risk")
@_login_required
def update_transfer_risk_settings(user):
    if not _is_admin(user):
        return _json_error("Admin access is required.", 403)
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    value = _payload().get("amount_ratio_limit")
    if isinstance(value, bool) or not str(value).isdigit():
        return _json_error("Enter a whole-number threshold from 1 to 100.", 400)
    threshold = int(value)
    if not 1 <= threshold <= 100:
        return _json_error("Enter a whole-number threshold from 1 to 100.", 400)
    with transaction(immediate=True) as connection:
        updated = connection.execute(
            """
            UPDATE app_settings SET setting_value = ?
            WHERE setting_key = 'transfer_risk_ratio_limit'
            """,
            (threshold,),
        )
        if updated.rowcount != 1:
            raise RuntimeError("The transfer risk threshold setting is unavailable.")
    return jsonify(
        {
            "message": f"Transfer risk threshold set to {threshold}x the typical amount.",
            "amount_ratio_limit": threshold,
        }
    )


@app.post("/api/admin/accounts/<int:account_id>/unlock")
@_login_required
def unlock_account(user, account_id: int):
    if not _is_admin(user):
        return _json_error("Admin access is required.", 403)
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    with transaction(immediate=True) as connection:
        unlocked = connection.execute(
            """
            UPDATE users SET account_status = 'active', failed_login_attempts = 0,
                account_locked_at = NULL, locked_until = 0
            WHERE id = ? AND account_status = 'locked'
            """,
            (account_id,),
        )
        if unlocked.rowcount != 1:
            return _json_error("The locked account was not found.", 404)
        _audit_in_transaction(
            connection,
            user["id"],
            "Account unlocked by administrator",
            {"customer_id": account_id},
        )
    return jsonify({"message": "Account unlocked. The customer can sign in again."})


@app.post("/api/admin/accounts/<int:account_id>/transfer-access")
@_login_required
def update_transfer_access(user, account_id: int):
    if not _is_admin(user):
        return _json_error("Admin access is required.", 403)
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    enabled = _payload().get("can_transfer")
    if not isinstance(enabled, bool):
        return _json_error("Transfer access must be enabled or disabled.", 400)
    with transaction(immediate=True) as connection:
        updated = connection.execute(
            "UPDATE users SET can_transfer = ? WHERE id = ? AND id != ?",
            (int(enabled), account_id, user["id"]),
        )
        if updated.rowcount != 1:
            return _json_error("The customer account was not found.", 404)
        _audit_in_transaction(
            connection,
            user["id"],
            "Customer transfers enabled" if enabled else "Customer transfers blocked",
            {"customer_id": account_id},
        )
    return jsonify(
        {
            "message": (
                "Transfers enabled for this customer."
                if enabled
                else "Transfers blocked for this customer."
            ),
            "can_transfer": enabled,
        }
    )


@app.get("/api/risk-data")
@_login_required
def risk_data(user):
    return jsonify(_monitor_data(user["id"]))


@app.post("/api/register")
def register():
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    data = _payload()
    if "initial_deposit" in data:
        return _json_error(
            "Opening balances cannot be set during registration.",
            400,
        )
    full_name = sanitize_plain_text(str(data.get("full_name", "")), 100)
    national_id = str(data.get("national_id", "")).strip()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip()
    phone = str(data.get("phone", "")).strip()
    password = str(data.get("password", ""))
    payment_pin = str(data.get("payment_pin", "")).strip()
    payment_pin_confirm = str(data.get("payment_pin_confirm", "")).strip()
    initial_cents = REGISTRATION_OPENING_BALANCE_CENTS
    if not full_name or len(full_name) < 2:
        return _json_error("Enter your full name.", 400)
    if not NATIONAL_ID_PATTERN.fullmatch(national_id):
        return _json_error("National ID must contain 6 to 20 digits.", 400)
    if not USERNAME_PATTERN.fullmatch(username):
        return _json_error(
            "Username must start with a letter and contain 3 to 30 letters, digits, "
            "periods, underscores, or hyphens.",
            400,
        )
    if username.casefold() == app.config["ADMIN_USERNAME"].casefold():
        return _json_error(
            "The administrator username is reserved and cannot be created through public registration.",
            403,
        )
    if not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        return _json_error("Enter a valid email address.", 400)
    if not PHONE_PATTERN.fullmatch(phone):
        return _json_error("Phone number must contain 7 to 15 digits.", 400)
    if not PASSWORD_PATTERN.fullmatch(password):
        return _json_error(
            "Password must be 8 to 128 characters and include uppercase, lowercase, "
            "a number, and a symbol.",
            400,
        )
    if not PAYMENT_PIN_PATTERN.fullmatch(payment_pin):
        return _json_error("Payment Password must contain exactly six digits.", 400)
    if payment_pin != payment_pin_confirm:
        return _json_error("Payment Password entries do not match.", 400)
    salt, password_digest = hash_password(password)
    pin_salt, pin_digest = hash_payment_pin(payment_pin)
    account_number = None
    try:
        with transaction(immediate=True) as connection:
            for _ in range(5):
                candidate = f"{secrets.randbelow(10_000_000_000):010d}"
                exists = connection.execute(
                    "SELECT 1 FROM users WHERE account_number = ?", (candidate,)
                ).fetchone()
                if exists is None:
                    account_number = candidate
                    break
            if account_number is None:
                return _json_error("Unable to allocate an account number. Retry.", 503)
            cursor = connection.execute(
                """
                INSERT INTO users
                    (full_name, national_id_ciphertext, username, email, phone,
                     account_number, password_salt, password_hash, balance_cents,
                     opening_balance_cents, payment_pin_salt, payment_pin_hash,
                     created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    full_name,
                    encrypt_sensitive_value(national_id),
                    username,
                    email,
                    phone,
                    account_number,
                    salt,
                    password_digest,
                    initial_cents,
                    initial_cents,
                    pin_salt,
                    pin_digest,
                    _now(),
                ),
            )
            user_id = cursor.lastrowid
            _audit_in_transaction(
                connection,
                user_id,
                "Account registered",
                {},
            )
    except sqlite3.IntegrityError:
        return _json_error("Username, email, or generated account number is already in use.", 409)
    with balance_index_lock:
        balance_index.insert(user_id, initial_cents)
    return jsonify(
        {
            "message": "Registration completed. Sign in to continue.",
            "account_number": account_number,
        }
    ), 201


@app.post("/api/login")
def login():
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    data = _payload()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    device_hash = _device_hash(data.get("device_id"))
    latitude, longitude = _coordinates(data)
    if not username or not password or device_hash is None:
        return _json_error("Enter your username, password, and a valid browser device ID.", 400)
    throttle_keys = _login_throttle_keys(username)
    now = _now()
    connection = connect()
    try:
        user = connection.execute(
            """
            SELECT * FROM users
            WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
            """,
            (username, username),
        ).fetchone()
    finally:
        connection.close()
    if user is not None and (
        user["account_status"] == "locked" or user["locked_until"] > now
    ):
        _record_login_attempt(
            username, user["id"], device_hash, "account_locked"
        )
        return _json_error(
            "This account is locked. Contact the administrator to restore access.", 423
        )
    connection = connect()
    try:
        throttled = connection.execute(
            """
            SELECT 1 FROM auth_throttles
            WHERE throttle_key IN (?, ?) AND locked_until > ?
            LIMIT 1
            """,
            (*throttle_keys, now),
        ).fetchone()
    finally:
        connection.close()
    if throttled:
        _record_login_attempt(
            username,
            user["id"] if user is not None else None,
            device_hash,
            "throttled",
        )
        return _json_error("Too many failed attempts. Try again later.", 429)
    if user is None:
        verify_password(password, _DUMMY_SALT, _DUMMY_PASSWORD_HASH)
        with transaction(immediate=True) as connection:
            _record_failed_login(
                connection, None, throttle_keys, now, username, device_hash
            )
        _record_login_attempt(username, None, device_hash, "invalid_credentials")
        return _json_error("Invalid username or password.", 401)
    if not verify_password(password, user["password_salt"], user["password_hash"]):
        with transaction(immediate=True) as connection:
            locked = _record_failed_login(
                connection, user["id"], throttle_keys, now, username, device_hash
            )
        if locked:
            return _json_error(
                "This account is locked after three failed attempts. Contact the administrator.",
                423,
            )
        return _json_error("Invalid username or password.", 401)

    with transaction(immediate=True) as connection:
        reset = connection.execute(
            """
            UPDATE users SET failed_login_attempts = 0, locked_until = 0
            WHERE id = ? AND account_status = 'active' AND locked_until <= ?
            """,
            (user["id"], now),
        )
        if reset.rowcount != 1:
            return _json_error(
                "This account is locked. Contact the administrator to restore access.",
                423,
            )

    if not is_bcrypt_password_hash(user["password_hash"]):
        upgraded_salt, upgraded_hash = hash_password(password)
        with transaction(immediate=True) as connection:
            upgraded = connection.execute(
                """
                UPDATE users SET password_salt = ?, password_hash = ?
                WHERE id = ? AND password_salt = ? AND password_hash = ?
                """,
                (
                    upgraded_salt,
                    upgraded_hash,
                    user["id"],
                    user["password_salt"],
                    user["password_hash"],
                ),
            )
            if upgraded.rowcount != 1:
                return _json_error(
                    "Account credentials changed. Please sign in again.", 409
                )
            _audit_in_transaction(
                connection,
                user["id"],
                "Password hash upgraded",
                {},
            )

    features = _risk_features_for_login(
        user["id"], device_hash, latitude, longitude
    )
    assessment = risk_engine.assess(features, block_on_model_consensus=True)
    _record_risk_event(user["id"], "login", assessment)
    if not _risk_allows_login(assessment, user["id"]):
        _record_login_attempt(
            username,
            user["id"],
            device_hash,
            "risk_blocked",
            risk_level=str(assessment["level"]),
            risk_score=float(assessment["score"]),
        )
        return jsonify(
            {
                "error": "Sign-in blocked because the activity is high risk.",
                "risk": assessment,
            }
        ), 403

    verification_method = (
        "totp"
        if user["mfa_enabled"]
        else "payment_pin"
        if assessment["action"] == "require_pin"
        else None
    )
    if verification_method:
        _record_login_attempt(
            username,
            user["id"],
            device_hash,
            "step_up_required",
            risk_level=str(assessment["level"]),
            risk_score=float(assessment["score"]),
        )
        challenge_id = _create_login_challenge(
            user["id"],
            device_hash,
            latitude,
            longitude,
            verification_method,
            str(assessment["level"]),
            float(assessment["score"]),
        )
        _audit(
            user["id"],
            "Authenticator MFA sign-in challenge"
            if verification_method == "totp"
            else "Medium-risk login requires Payment Password verification",
        )
        return jsonify(
            {
                "message": (
                    "Verify your authenticator code to complete this sign-in."
                    if verification_method == "totp"
                    else "Verify your Payment Password to complete this sign-in."
                ),
                "verification_required": True,
                "verification_method": verification_method,
                "challenge_id": challenge_id,
                "risk": assessment,
            }
        )

    _record_login(
        user["id"],
        username,
        device_hash,
        latitude,
        longitude,
        str(assessment["level"]),
        float(assessment["score"]),
    )
    _create_session(user)
    destination_endpoint = "admin_dashboard" if _is_admin(user) else "dashboard"
    return jsonify(
        {"message": "Sign-in successful.", "redirect": url_for(destination_endpoint)}
    )


@app.post("/api/login/verify")
def verify_login_challenge():
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    data = _payload()
    challenge_id = data.get("challenge_id")
    factor_code = str(data.get("totp_code", data.get("payment_pin", ""))).strip()
    if not isinstance(challenge_id, str) or not 32 <= len(challenge_id) <= 64:
        return _json_error("The sign-in verification challenge is invalid.", 400)

    challenge_hash = hash_token(challenge_id)
    now = _now()
    connection = connect()
    try:
        challenge = connection.execute(
            """
            SELECT user_id, device_hash, latitude, longitude, expires_at,
                   verification_method, risk_level, risk_score
            FROM login_challenges WHERE challenge_hash = ?
            """,
            (challenge_hash,),
        ).fetchone()
    finally:
        connection.close()
    if challenge is None:
        return _json_error("The sign-in challenge is invalid or already used.", 400)
    if challenge["expires_at"] <= now:
        with transaction(immediate=True) as connection:
            connection.execute(
                "DELETE FROM login_challenges WHERE challenge_hash = ?",
                (challenge_hash,),
            )
        return _json_error("The sign-in challenge expired. Please sign in again.", 410)

    if challenge["verification_method"] == "totp":
        if not (
            (len(factor_code) == 6 and factor_code.isascii() and factor_code.isdigit())
            or (
                len(factor_code) == 16
                and factor_code.isascii()
                and re.fullmatch(r"[A-Fa-f0-9]{16}", factor_code)
            )
        ):
            return _json_error("Enter a six-digit authenticator code or recovery code.", 400)
        with transaction(immediate=True) as connection:
            valid, locked = _consume_mfa_code(
                connection,
                challenge["user_id"],
                factor_code,
                now,
            )
            if not valid:
                attempts = connection.execute(
                    "UPDATE login_challenges SET attempts = attempts + 1 "
                    "WHERE challenge_hash = ?",
                    (challenge_hash,),
                )
                if attempts.rowcount != 1:
                    return _json_error("The sign-in challenge is invalid.", 400)
                connection.execute(
                    "DELETE FROM login_challenges WHERE challenge_hash = ? "
                    "AND attempts >= ?",
                    (challenge_hash, app.config["MFA_MAX_ATTEMPTS"]),
                )
        if locked:
            _audit(challenge["user_id"], "Authenticator MFA temporarily locked")
            return _json_error("Authenticator verification is temporarily locked.", 423)
        if not valid:
            _audit(challenge["user_id"], "Authenticator sign-in verification failed")
            return _json_error("The authenticator or recovery code is invalid.", 401)
    else:
        if not PAYMENT_PIN_PATTERN.fullmatch(factor_code):
            return _json_error("Enter your six-digit Payment Password.", 400)
        pin_valid, pin_locked = _verify_user_payment_pin(
            challenge["user_id"], factor_code
        )
        if pin_locked:
            _audit(challenge["user_id"], "Medium-risk login verification locked")
            return _json_error(
                "Too many incorrect Payment Password attempts. Try again later.", 423
            )
        if not pin_valid:
            with transaction(immediate=True) as connection:
                connection.execute(
                    """
                    UPDATE login_challenges SET attempts = attempts + 1
                    WHERE challenge_hash = ?
                    """,
                    (challenge_hash,),
                )
                connection.execute(
                    "DELETE FROM login_challenges WHERE challenge_hash = ? "
                    "AND attempts >= ?",
                    (challenge_hash, app.config["PAYMENT_PIN_MAX_ATTEMPTS"]),
                )
            _audit(challenge["user_id"], "Medium-risk login verification failed")
            return _json_error("Incorrect Payment Password.", 401)

    with transaction(immediate=True) as connection:
        consumed = connection.execute(
            """
            DELETE FROM login_challenges
            WHERE challenge_hash = ? AND expires_at > ?
            """,
            (challenge_hash, now),
        )
        user = connection.execute(
            "SELECT * FROM users WHERE id = ? AND account_status = 'active'",
            (challenge["user_id"],),
        ).fetchone()
        if consumed.rowcount != 1 or user is None:
            return _json_error("The sign-in challenge is invalid or already used.", 400)
        _audit_in_transaction(
            connection,
            user["id"],
            "Login step-up verification completed",
            {},
            now,
        )

    _record_login(
        user["id"],
        user["username"],
        challenge["device_hash"],
        challenge["latitude"],
        challenge["longitude"],
        challenge["risk_level"] or "MEDIUM",
        float(challenge["risk_score"] or 0.5),
    )
    _create_session(user)
    destination_endpoint = "admin_dashboard" if _is_admin(user) else "dashboard"
    return jsonify(
        {
            "message": "Verification complete. Sign-in successful.",
            "redirect": url_for(destination_endpoint),
        }
    )


@app.post("/api/otp/verify")
def verify_otp():
    return _json_error(
        "One-time codes are no longer used. Sign in with your username and password.", 410
    )


@app.post("/api/transfer")
@_login_required
def transfer(user):
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    data = _payload()
    destination = str(data.get("recipient", "")).strip()
    amount_cents = _amount_cents(data.get("amount"))
    reference = sanitize_plain_text(str(data.get("reference", "")), 140)
    payment_pin = str(data.get("payment_pin", "")).strip()
    if not destination or len(destination) > 30 or amount_cents is None:
        return _json_error("Enter a valid recipient and an amount with at most two decimals.", 400)
    if not PAYMENT_PIN_PATTERN.fullmatch(payment_pin):
        return _json_error("Enter your six-digit Payment Password to authorize this transfer.", 400)
    if not reference and data.get("reference"):
        return _json_error("Reference note contains no valid text.", 400)
    if not user["can_transfer"]:
        return _json_error(
            "Transfers are disabled for this account. Contact the administrator.", 403
        )
    connection = connect()
    try:
        recipient = _recipient(connection, destination)
        if recipient is None:
            return _json_error("The recipient was not found.", 404)
        if recipient["id"] == user["id"]:
            return _json_error("Transfers to the same account are not allowed.", 400)
    finally:
        connection.close()

    assessment = _transfer_risk(user["id"], amount_cents)
    if not _risk_allows_transfer(assessment, user["id"]):
        return jsonify(
            {
                "error": "Transfer blocked because the activity is high risk.",
                "risk": assessment,
                "status": "blocked",
            }
        ), 403
    pin_valid, pin_locked = _verify_user_payment_pin(user["id"], payment_pin)
    if pin_locked:
        return _json_error(
            "Too many incorrect Payment Password attempts. Try again later.", 423
        )
    if not pin_valid:
        return _json_error("Incorrect Payment Password.", 401)
    if amount_cents >= app.config["HIGH_VALUE_TRANSFER_CENTS"]:
        if not user["mfa_enabled"]:
            _audit(user["id"], "High-value transfer denied because authenticator MFA is disabled")
            return _json_error(
                "Enable authenticator MFA in Profile Settings before transferring $1,000 or more.",
                403,
            )
        totp_code = str(data.get("totp_code", "")).strip()
        with transaction(immediate=True) as connection:
            mfa_valid, mfa_locked = _consume_mfa_code(
                connection,
                user["id"],
                totp_code,
                _now(),
            )
            if mfa_locked:
                return _json_error("Authenticator verification is temporarily locked.", 423)
            if not mfa_valid:
                return _json_error(
                    "A valid, unused authenticator or recovery code is required for this high-value transfer.",
                    401,
                )
    try:
        return jsonify(_execute_transfer(user["id"], {
            "recipient": destination,
            "amount": data.get("amount"),
            "reference": reference,
            "idempotency_key": data.get("idempotency_key"),
        }))
    except TransferConflict as exc:
        return _json_error(str(exc), 409)
    except ValueError as exc:
        return _json_error(str(exc), 400)
    except LookupError as exc:
        return _json_error(str(exc), 404)
    except PermissionError as exc:
        return _json_error(str(exc), 403)


@app.get("/api/receipt/<receipt_reference>")
@_login_required
def receipt_data(user, receipt_reference):
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,40}", receipt_reference):
        return _json_error("Receipt was not found.", 404)
    connection = connect()
    try:
        receipt = connection.execute(
            """
            SELECT t.id, t.receipt_reference, t.amount_cents, t.reference,
                   t.reference_ciphertext,
                   t.created_at, sender.full_name AS sender_name,
                   sender.account_number AS sender_account,
                   recipient.full_name AS recipient_name,
                   recipient.account_number AS recipient_account,
                   t.sender_id, t.recipient_id
            FROM transfers AS t
            JOIN users AS sender ON sender.id = t.sender_id
            JOIN users AS recipient ON recipient.id = t.recipient_id
            WHERE t.receipt_reference = ?
            """,
            (receipt_reference,),
        ).fetchone()
    finally:
        connection.close()
    if receipt is None or user["id"] not in (receipt["sender_id"], receipt["recipient_id"]):
        return _json_error("Receipt was not found.", 404)
    verification_path = url_for(
        "verify_receipt", receipt_reference=receipt["receipt_reference"]
    )
    base_url = app.config["PUBLIC_BASE_URL"] or request.url_root.rstrip("/")
    verification_url = f"{base_url}{verification_path}"
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=5,
        border=2,
    )
    qr.add_data(verification_url)
    qr.make(fit=True)
    svg = BytesIO()
    qr.make_image(image_factory=qrcode.image.svg.SvgPathImage).save(svg)
    return jsonify(
        {
            "status": "SUCCESSFUL",
            "transaction_id": f"FB-{receipt['id']:010d}",
            "receipt_reference": receipt["receipt_reference"],
            "created_at": receipt["created_at"],
            "sender_name": receipt["sender_name"],
            "sender_account": receipt["sender_account"],
            "recipient_name": receipt["recipient_name"],
            "recipient_account": receipt["recipient_account"],
            "amount": f"{receipt['amount_cents'] / 100:.2f}",
            "fee": "0.00",
            "reference": _transfer_reference(receipt),
            "verification_url": verification_url,
            "qr_data": (
                "data:image/svg+xml;base64,"
                + base64.b64encode(svg.getvalue()).decode("ascii")
            ),
        }
    )


@app.get("/receipt/verify/<receipt_reference>")
def verify_receipt(receipt_reference):
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,40}", receipt_reference):
        abort(404)
    connection = connect()
    try:
        receipt = connection.execute(
            """
            SELECT id, amount_cents, created_at
            FROM transfers WHERE receipt_reference = ?
            """,
            (receipt_reference,),
        ).fetchone()
    finally:
        connection.close()
    if receipt is None:
        abort(404)
    return render_template(
        "receipt_verify.html",
        receipt={
            "transaction_id": f"FB-{receipt['id']:010d}",
            "amount": f"{receipt['amount_cents'] / 100:.2f}",
            "created_at": receipt["created_at"],
        },
    )


@app.post("/api/logout")
@_login_required
def logout(user):
    csrf_error = _require_csrf()
    if csrf_error:
        return _json_error(str(csrf_error[0]["error"]), csrf_error[1])
    token = session.get("session_token")
    with transaction(immediate=True) as connection:
        connection.execute(
            "UPDATE sessions SET revoked = 1 WHERE token_hash = ?",
            (hash_token(token),),
        )
        _audit_in_transaction(
            connection,
            user["id"],
            "Session logged out",
            {},
        )
    session.clear()
    return jsonify({"redirect": url_for("index")})


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "mode": "demonstration"})


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False,
    )
