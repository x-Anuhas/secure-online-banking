"""SQLite schema and transaction helpers for the banking demonstration."""

import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

from flask import current_app


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    national_id_ciphertext BLOB NOT NULL,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    role TEXT NOT NULL DEFAULT 'customer'
        CHECK (role IN ('customer', 'admin')),
    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
    phone TEXT NOT NULL,
    account_number TEXT NOT NULL UNIQUE,
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0),
    opening_balance_cents INTEGER NOT NULL CHECK (opening_balance_cents >= 0),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    account_status TEXT NOT NULL DEFAULT 'active'
        CHECK (account_status IN ('active', 'locked')),
    can_transfer INTEGER NOT NULL DEFAULT 1 CHECK (can_transfer IN (0, 1)),
    account_locked_at INTEGER,
    locked_until INTEGER NOT NULL DEFAULT 0,
    payment_pin_salt TEXT,
    payment_pin_hash TEXT,
    failed_pin_attempts INTEGER NOT NULL DEFAULT 0,
    pin_locked_until INTEGER NOT NULL DEFAULT 0,
    mfa_secret_ciphertext BLOB,
    mfa_pending_secret_ciphertext BLOB,
    mfa_enabled INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1)),
    last_mfa_counter INTEGER NOT NULL DEFAULT -1,
    mfa_failed_attempts INTEGER NOT NULL DEFAULT 0,
    mfa_locked_until INTEGER NOT NULL DEFAULT 0,
    profile_image TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS known_devices (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, device_hash)
);

CREATE TABLE IF NOT EXISTS auth_throttles (
    throttle_key TEXT PRIMARY KEY,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username_hash TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    device_hash TEXT,
    outcome TEXT NOT NULL CHECK (
        outcome IN (
            'invalid_credentials', 'account_locked', 'throttled',
            'risk_blocked', 'step_up_required', 'success'
        )
    ),
    risk_level TEXT CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    risk_score REAL CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 1),
    occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
    ON login_attempts(user_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time
    ON login_attempts(username_hash, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip_hash, occurred_at DESC);

CREATE TABLE IF NOT EXISTS otp_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_hash TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('login', 'transfer')),
    payload_json TEXT,
    device_hash TEXT,
    latitude REAL,
    longitude REAL,
    verification_method TEXT NOT NULL DEFAULT 'payment_pin',
    risk_level TEXT CHECK (risk_level IS NULL OR risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    risk_score REAL CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 1),
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    occurred_at INTEGER NOT NULL,
    latitude REAL,
    longitude REAL
);
CREATE INDEX IF NOT EXISTS idx_login_events_user_time
    ON login_events(user_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS login_challenges (
    challenge_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_challenges_expiry
    ON login_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_login_challenges_user
    ON login_challenges(user_id);

CREATE TABLE IF NOT EXISTS risk_events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN ('login', 'transfer')),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH')),
    risk_score REAL NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 1),
    action TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    features_json TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_events_time
    ON risk_events(occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_user_time
    ON risk_events(user_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS access_events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_events_user_time
    ON access_events(user_id, occurred_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS transfers (
    id INTEGER PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    reference TEXT NOT NULL,
    reference_ciphertext BLOB,
    receipt_reference TEXT UNIQUE,
    idempotency_key TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transfers_sender_time
    ON transfers(sender_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfers_recipient_time
    ON transfers(recipient_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ledger_entries (
    id INTEGER PRIMARY KEY,
    transfer_id INTEGER NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    direction TEXT NOT NULL CHECK (direction IN ('debit', 'credit')),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_user_time
    ON ledger_entries(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user_time
    ON audit_events(user_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    used_at INTEGER,
    PRIMARY KEY (user_id, code_hash)
);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user
    ON mfa_recovery_codes(user_id, used_at);

CREATE TABLE IF NOT EXISTS audit_chain (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    operation TEXT NOT NULL,
    details_json TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_audit_chain_user_time
    ON audit_chain(user_id, occurred_at DESC, id DESC);
CREATE TRIGGER IF NOT EXISTS prevent_audit_chain_update
BEFORE UPDATE ON audit_chain
BEGIN
    SELECT RAISE(ABORT, 'audit chain entries are immutable');
END;
CREATE TRIGGER IF NOT EXISTS prevent_audit_chain_delete
BEFORE DELETE ON audit_chain
BEGIN
    SELECT RAISE(ABORT, 'audit chain entries are immutable');
END;

CREATE TABLE IF NOT EXISTS security_incidents (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL,
    risk_score REAL NOT NULL CHECK (risk_score BETWEEN 0 AND 1),
    details_json TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    audit_entry_hash TEXT NOT NULL REFERENCES audit_chain(entry_hash)
);
CREATE INDEX IF NOT EXISTS idx_security_incidents_time
    ON security_incidents(occurred_at DESC, id DESC);
CREATE TRIGGER IF NOT EXISTS prevent_security_incident_update
BEFORE UPDATE ON security_incidents
BEGIN
    SELECT RAISE(ABORT, 'security incidents are immutable');
END;
CREATE TRIGGER IF NOT EXISTS prevent_security_incident_delete
BEFORE DELETE ON security_incidents
BEGIN
    SELECT RAISE(ABORT, 'security incidents are immutable');
END;

CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value INTEGER NOT NULL CHECK (setting_value BETWEEN 1 AND 100)
);
"""


def connect() -> sqlite3.Connection:
    """Open a configured SQLite connection with integrity checks enabled."""
    connection = sqlite3.connect(
        current_app.config["DATABASE_PATH"],
        timeout=10,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


@contextmanager
def transaction(immediate: bool = False) -> Iterator[sqlite3.Connection]:
    """Yield a connection and commit atomically, rolling back on any failure."""
    connection = connect()
    try:
        connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    """Create the schema and enable write-ahead logging."""
    connection = connect()
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(SCHEMA)
        user_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(users)")
        }
        for column, definition in (
            ("role", "TEXT NOT NULL DEFAULT 'customer'"),
            ("failed_login_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("account_status", "TEXT NOT NULL DEFAULT 'active'"),
            ("can_transfer", "INTEGER NOT NULL DEFAULT 1 CHECK (can_transfer IN (0, 1))"),
            ("account_locked_at", "INTEGER"),
            ("locked_until", "INTEGER NOT NULL DEFAULT 0"),
            ("payment_pin_salt", "TEXT"),
            ("payment_pin_hash", "TEXT"),
            ("failed_pin_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("pin_locked_until", "INTEGER NOT NULL DEFAULT 0"),
            ("mfa_secret_ciphertext", "BLOB"),
            ("mfa_pending_secret_ciphertext", "BLOB"),
            ("mfa_enabled", "INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0, 1))"),
            ("last_mfa_counter", "INTEGER NOT NULL DEFAULT -1"),
            ("mfa_failed_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("mfa_locked_until", "INTEGER NOT NULL DEFAULT 0"),
            ("profile_image", "TEXT"),
        ):
            if column not in user_columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        challenge_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(login_challenges)")
        }
        if "verification_method" not in challenge_columns:
            connection.execute(
                "ALTER TABLE login_challenges ADD COLUMN "
                "verification_method TEXT NOT NULL DEFAULT 'payment_pin'"
            )
        if "risk_level" not in challenge_columns:
            connection.execute(
                "ALTER TABLE login_challenges ADD COLUMN risk_level TEXT"
            )
        if "risk_score" not in challenge_columns:
            connection.execute(
                "ALTER TABLE login_challenges ADD COLUMN risk_score REAL"
            )
        risk_event_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(risk_events)")
        }
        if "risk_score" not in risk_event_columns:
            connection.execute(
                "ALTER TABLE risk_events ADD COLUMN "
                "risk_score REAL NOT NULL DEFAULT 0"
            )
        current_time = int(time.time())
        connection.execute(
            """
            UPDATE users SET account_status = 'locked',
                account_locked_at = COALESCE(account_locked_at, ?)
            WHERE account_status = 'active'
              AND (failed_login_attempts >= 3 OR locked_until > ?)
            """,
            (current_time, current_time),
        )
        transfer_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(transfers)")
        }
        if "reference_ciphertext" not in transfer_columns:
            connection.execute(
                "ALTER TABLE transfers ADD COLUMN reference_ciphertext BLOB"
            )
        if "receipt_reference" not in transfer_columns:
            connection.execute("ALTER TABLE transfers ADD COLUMN receipt_reference TEXT")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_transfers_receipt_reference "
                "ON transfers(receipt_reference)"
            )
        if "idempotency_key" not in transfer_columns:
            connection.execute("ALTER TABLE transfers ADD COLUMN idempotency_key TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_transfers_sender_idempotency "
            "ON transfers(sender_id, idempotency_key) WHERE idempotency_key IS NOT NULL"
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO app_settings (setting_key, setting_value)
            VALUES ('transfer_risk_ratio_limit', 5)
            """
        )
        configured_admin = current_app.config["ADMIN_USERNAME"].casefold()
        connection.execute(
            "UPDATE users SET role = 'customer' WHERE role = 'admin' AND username != ?",
            (configured_admin,),
        )
        connection.execute(
            "UPDATE users SET role = 'admin' WHERE username = ? COLLATE NOCASE",
            (configured_admin,),
        )
    finally:
        connection.close()
