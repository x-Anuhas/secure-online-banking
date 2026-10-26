"""Focused regression tests for authentication boundaries and simulated transfers."""

import hashlib
import hmac
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path

import pyotp

from app import (
    REGISTRATION_OPENING_BALANCE_CENTS,
    _execute_transfer,
    _risk_features_for_login,
    _transfer_risk,
    app,
)
from audit_chain import append_audit_entry, verify_audit_chain
from database import SCHEMA, connect, initialize_database
from graph_analyzer import AccessGraph
from mfa_security import hash_recovery_code
from risk_engine import RiskEngine, RiskFeatures
from security import (
    hash_password,
    hash_payment_pin,
    hash_token,
    verify_password,
)
from avl_tree import AVLTree


class SecurityIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temporary_directory.name) / "tests.sqlite3")
        self.previous_database_path = app.config["DATABASE_PATH"]
        self.previous_admin_username = app.config["ADMIN_USERNAME"]
        app.config.update(TESTING=True, DATABASE_PATH=self.database_path)
        with app.app_context():
            initialize_database()
            pin_salt, pin_digest = hash_payment_pin("123456")
            with closing(connect()) as connection:
                connection.executemany(
                    """
                    INSERT INTO users
                        (full_name, national_id_ciphertext, username, email, phone,
                         account_number, password_salt, password_hash, balance_cents,
                         opening_balance_cents, payment_pin_salt, payment_pin_hash,
                         created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        (
                            "Test Sender",
                            b"encrypted-id",
                            "sender",
                            "sender@example.test",
                            "1234567890",
                            "1000000001",
                            "salt",
                            "hash",
                            100_000,
                            100_000,
                            pin_salt,
                            pin_digest,
                            int(time.time()),
                        ),
                        (
                            "Test Recipient",
                            b"encrypted-id",
                            "recipient",
                            "recipient@example.test",
                            "1234567891",
                            "1000000002",
                            "salt",
                            "hash",
                            0,
                            0,
                            pin_salt,
                            pin_digest,
                            int(time.time()),
                        ),
                    ),
                )

        self.client = app.test_client()
        self.csrf_token = secrets.token_urlsafe(32)
        self.session_token = secrets.token_urlsafe(32)
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    (hash_token(self.session_token), 1, int(time.time()) + 1800),
                )
        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = 1
            browser_session["session_token"] = self.session_token
            browser_session["csrf_token"] = self.csrf_token

    def tearDown(self) -> None:
        app.config["DATABASE_PATH"] = self.previous_database_path
        app.config["ADMIN_USERNAME"] = self.previous_admin_username
        self.temporary_directory.cleanup()

    def _post_transfer(
        self,
        *,
        amount: str = "25.00",
        idempotency_key: str = "audit-request-key-0001",
    ):
        return self.client.post(
            "/api/transfer",
            headers={"X-CSRF-Token": self.csrf_token},
            json={
                "recipient": "recipient",
                "amount": amount,
                "reference": "test transfer",
                "payment_pin": "123456",
                "idempotency_key": idempotency_key,
            },
        )

    def _balances_and_transfer_counts(self) -> tuple[list[int], int, int]:
        with app.app_context():
            with closing(connect()) as connection:
                balances = [
                    row["balance_cents"]
                    for row in connection.execute(
                        "SELECT balance_cents FROM users ORDER BY id"
                    )
                ]
                transfers = connection.execute(
                    "SELECT COUNT(*) AS count FROM transfers"
                ).fetchone()["count"]
                ledger_entries = connection.execute(
                    "SELECT COUNT(*) AS count FROM ledger_entries"
                ).fetchone()["count"]
        return balances, transfers, ledger_entries

    def _authenticate_as(self, user_id: int) -> None:
        token = secrets.token_urlsafe(32)
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "INSERT INTO sessions (token_hash, user_id, expires_at) "
                    "VALUES (?, ?, ?)",
                    (hash_token(token), user_id, int(time.time()) + 1800),
                )
        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = user_id
            browser_session["session_token"] = token

    def _grant_admin_role(self, user_id: int) -> None:
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET role = 'customer' WHERE role = 'admin'"
                )
                connection.execute(
                    "UPDATE users SET role = 'admin' WHERE id = ?", (user_id,)
                )

    def _trust_login_device(self, user_id: int = 1) -> None:
        device_id = "device_identifier_123456"
        now = int(time.time())
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    """
                    INSERT INTO known_devices
                        (user_id, device_hash, first_seen_at, last_seen_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, hash_token(device_id), now, now),
                )

    def test_registration_cannot_set_opening_balance(self) -> None:
        registration = {
            "full_name": "New Customer",
            "national_id": "123456789012",
            "username": "newcustomer",
            "email": "newcustomer@example.test",
            "phone": "1234567890",
            "password": "Aa1!abcd",
            "payment_pin": "123456",
            "payment_pin_confirm": "123456",
            "csrf_token": self.csrf_token,
            "initial_deposit": "999999.99",
        }
        rejected = self.client.post("/api/register", json=registration)
        self.assertEqual(rejected.status_code, 400)
        self.assertIn("cannot be set", rejected.get_json()["error"])

        registration.pop("initial_deposit")
        registration["password"] = "Aa1!abc"
        too_short = self.client.post("/api/register", json=registration)
        self.assertEqual(too_short.status_code, 400)
        self.assertIn("8 to 128", too_short.get_json()["error"])

        registration["password"] = "Aa1!abcd"
        created = self.client.post("/api/register", json=registration)
        self.assertEqual(created.status_code, 201)
        with app.app_context():
            with closing(connect()) as connection:
                user = connection.execute(
                    "SELECT balance_cents, opening_balance_cents FROM users "
                    "WHERE username = ?",
                    ("newcustomer",),
                ).fetchone()
        self.assertIsNotNone(user)
        self.assertEqual(
            user["balance_cents"],
            REGISTRATION_OPENING_BALANCE_CENTS,
        )
        self.assertEqual(
            user["opening_balance_cents"],
            REGISTRATION_OPENING_BALANCE_CENTS,
        )
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        registration_page = self.client.get("/register")
        self.assertNotIn(b"Illustrative opening balance", registration_page.data)
        self.assertNotIn(b"initial-deposit", registration_page.data)

    def test_replayed_transfer_returns_original_receipt_without_second_debit(self) -> None:
        first = self._post_transfer()
        replay = self._post_transfer()

        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(
            replay.get_json()["transfer_id"],
            first.get_json()["transfer_id"],
        )
        self.assertEqual(replay.get_json()["receipt_id"], first.get_json()["receipt_id"])
        self.assertEqual(self._balances_and_transfer_counts(), ([97_500, 2_500], 1, 2))

    def test_reusing_transfer_key_for_different_details_is_rejected(self) -> None:
        first = self._post_transfer()
        conflict = self._post_transfer(amount="30.00")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(self._balances_and_transfer_counts(), ([97_500, 2_500], 1, 2))

    def test_missing_idempotency_key_is_rejected(self) -> None:
        response = self.client.post(
            "/api/transfer",
            headers={"X-CSRF-Token": self.csrf_token},
            json={
                "recipient": "recipient",
                "amount": "25.00",
                "payment_pin": "123456",
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._balances_and_transfer_counts(), ([100_000, 0], 0, 0))

    def test_invalid_transfer_amount_is_rejected_without_writes(self) -> None:
        response = self._post_transfer(amount="not-an-amount")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._balances_and_transfer_counts(), ([100_000, 0], 0, 0))

    def test_insufficient_funds_does_not_change_balances_or_ledger(self) -> None:
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET balance_cents = 99_998 WHERE id = 1"
                )
        response = self._post_transfer(amount="999.99")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._balances_and_transfer_counts(), ([99_998, 0], 0, 0))

    def test_account_transfer_block_prevents_api_transfer(self) -> None:
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET can_transfer = 0 WHERE id = 1"
                )

        response = self._post_transfer()

        self.assertEqual(response.status_code, 403)
        self.assertIn("Transfers are disabled", response.get_json()["error"])
        self.assertEqual(self._balances_and_transfer_counts(), ([100_000, 0], 0, 0))

    def test_successful_transfer_persists_balances_ledger_and_audit(self) -> None:
        response = self._post_transfer(
            amount="25.00",
            idempotency_key="persistence-request-0001",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._balances_and_transfer_counts(), ([97_500, 2_500], 1, 2))
        with app.app_context():
            with closing(connect()) as connection:
                transfer_id = connection.execute(
                    "SELECT id FROM transfers"
                ).fetchone()["id"]
                stored_transfer = connection.execute(
                    "SELECT reference, reference_ciphertext FROM transfers WHERE id = ?",
                    (transfer_id,),
                ).fetchone()
                audit_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM audit_events "
                    "WHERE user_id = 1 AND event_type = 'Transfer'"
                ).fetchone()["count"]
                ledger_total = connection.execute(
                    "SELECT SUM(amount_cents) AS total FROM ledger_entries "
                    "WHERE transfer_id = ?",
                    (transfer_id,),
                ).fetchone()["total"]
                synchronous = connection.execute(
                    "PRAGMA synchronous"
                ).fetchone()[0]

        self.assertEqual(audit_count, 1)
        self.assertEqual(stored_transfer["reference"], "")
        self.assertIsNotNone(stored_transfer["reference_ciphertext"])
        self.assertEqual(ledger_total, 5_000)
        self.assertEqual(synchronous, 2)
        with app.app_context():
            with closing(connect()) as connection:
                chain = verify_audit_chain(connection)
        self.assertTrue(chain["valid"])
        self.assertGreaterEqual(chain["entries_checked"], 1)

    def test_high_risk_large_transfer_is_blocked_and_logged(self) -> None:
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET opening_balance_cents = 1_000 WHERE id = 1"
                )

        response = self._post_transfer(
            amount="60.00",
            idempotency_key="large-transfer-request-0001",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._balances_and_transfer_counts(), ([100_000, 0], 0, 0))
        with app.app_context():
            with closing(connect()) as connection:
                risk_event = connection.execute(
                    "SELECT event_type, risk_level, action, risk_score, features_json "
                    "FROM risk_events WHERE user_id = 1"
                ).fetchone()
                incident = connection.execute(
                    "SELECT risk_score, audit_entry_hash FROM security_incidents "
                    "WHERE user_id = 1"
                ).fetchone()
        self.assertEqual(risk_event["event_type"], "transfer")
        self.assertEqual(risk_event["risk_level"], "HIGH")
        self.assertEqual(risk_event["action"], "block")
        self.assertGreater(risk_event["risk_score"], 0.75)
        self.assertGreater(incident["risk_score"], 0.75)
        self.assertEqual(len(incident["audit_entry_hash"]), 64)
        self.assertIn("amount_ratio", risk_event["features_json"])

    def test_admin_can_update_transfer_risk_threshold(self) -> None:
        app.config["ADMIN_USERNAME"] = "SENDER"
        self._grant_admin_role(1)

        page = self.client.get("/admin/settings")
        response = self.client.post(
            "/api/admin/transfer-risk",
            headers={"X-CSRF-Token": self.csrf_token},
            json={"amount_ratio_limit": 8},
        )

        self.assertEqual(page.status_code, 200)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["amount_ratio_limit"], 8)
        with app.app_context():
            with closing(connect()) as connection:
                stored = connection.execute(
                    "SELECT setting_value FROM app_settings "
                    "WHERE setting_key = 'transfer_risk_ratio_limit'"
                ).fetchone()["setting_value"]
        self.assertEqual(stored, 8)

    def test_admin_routes_require_persisted_admin_role(self) -> None:
        app.config["ADMIN_USERNAME"] = "sender"
        response = self.client.get("/admin/dashboard")
        self.assertEqual(response.status_code, 403)

        self._grant_admin_role(1)
        authorized = self.client.get("/admin/dashboard")
        self.assertEqual(authorized.status_code, 200)

    def test_xanuhas_login_redirects_to_admin_dashboard(self) -> None:
        app.config["ADMIN_USERNAME"] = "XANUHAS"
        password = "Strong-test-password-42!"
        self._trust_login_device()
        with app.app_context():
            salt, digest = hash_password(password)
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET username = 'Xanuhas', "
                    "password_salt = ?, password_hash = ?, role = 'admin' WHERE id = 1",
                    (salt, digest),
                )
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        response = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "xanuhas",
                "password": password,
                "device_id": "device_identifier_123456",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["redirect"], "/admin/dashboard")

    def test_admin_can_block_and_restore_customer_transfer_access(self) -> None:
        app.config["ADMIN_USERNAME"] = "recipient"
        self._grant_admin_role(2)
        self._authenticate_as(2)

        blocked = self.client.post(
            "/api/admin/accounts/1/transfer-access",
            headers={"X-CSRF-Token": self.csrf_token},
            json={"can_transfer": False},
        )
        enabled = self.client.post(
            "/api/admin/accounts/1/transfer-access",
            headers={"X-CSRF-Token": self.csrf_token},
            json={"can_transfer": True},
        )

        self.assertEqual(blocked.status_code, 200)
        self.assertFalse(blocked.get_json()["can_transfer"])
        self.assertEqual(enabled.status_code, 200)
        self.assertTrue(enabled.get_json()["can_transfer"])
        with app.app_context():
            with closing(connect()) as connection:
                allowed = connection.execute(
                    "SELECT can_transfer FROM users WHERE id = 1"
                ).fetchone()["can_transfer"]
        self.assertEqual(allowed, 1)

    def test_non_admin_cannot_change_customer_transfer_access(self) -> None:
        app.config["ADMIN_USERNAME"] = "someone-else"

        response = self.client.post(
            "/api/admin/accounts/2/transfer-access",
            headers={"X-CSRF-Token": self.csrf_token},
            json={"can_transfer": False},
        )

        self.assertEqual(response.status_code, 403)
        with app.app_context():
            with closing(connect()) as connection:
                allowed = connection.execute(
                    "SELECT can_transfer FROM users WHERE id = 2"
                ).fetchone()["can_transfer"]
        self.assertEqual(allowed, 1)

    def test_admin_dashboard_includes_system_transfer_ledger(self) -> None:
        self._post_transfer(amount="25.00", idempotency_key="ledger-view-transfer-0001")
        app.config["ADMIN_USERNAME"] = "recipient"
        self._grant_admin_role(2)
        self._authenticate_as(2)

        response = self.client.get("/admin/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"System transfer ledger", response.data)
        self.assertIn(b"sender", response.data)
        self.assertIn(b"recipient", response.data)
        self.assertIn(b"$25.00", response.data)
        self.assertIn(b"Login risk and transfer flags", response.data)
        self.assertIn(b"Access-path graph scans", response.data)
        self.assertIn(b"Recent account activity", response.data)

    def test_admin_dashboard_shows_privacy_preserving_login_attempts(self) -> None:
        app.config["ADMIN_USERNAME"] = "recipient"
        self._grant_admin_role(2)
        self._authenticate_as(2)
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    """
                    INSERT INTO login_attempts
                        (user_id, username_hash, ip_hash, device_hash, outcome,
                         risk_level, risk_score, occurred_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        1,
                        "username-digest",
                        "0123456789abcdef",
                        "fedcba9876543210",
                        "invalid_credentials",
                        None,
                        None,
                        int(time.time()),
                    ),
                )

        response = self.client.get("/admin/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Recent login attempts", response.data)
        self.assertIn(b"Invalid Credentials", response.data)
        self.assertIn(b"0123456789ab", response.data)
        self.assertIn(b"fedcba987654", response.data)
        self.assertNotIn(b"username-digest", response.data)

    def test_admin_dashboard_shows_graph_detected_denied_admin_path(self) -> None:
        app.config["ADMIN_USERNAME"] = "recipient"
        self._grant_admin_role(2)
        self._authenticate_as(2)
        with app.app_context():
            with closing(connect()) as connection:
                connection.executemany(
                    "INSERT INTO access_events (user_id, resource, occurred_at) "
                    "VALUES (1, ?, ?)",
                    [
                        ("Login", int(time.time()) - 3),
                        ("Database", int(time.time()) - 2),
                        ("Admin denied", int(time.time()) - 1),
                    ],
                )

        response = self.client.get("/admin/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Login", response.data)
        self.assertIn(b"Admin denied", response.data)

    def test_non_admin_cannot_view_or_change_transfer_risk_threshold(self) -> None:
        app.config["ADMIN_USERNAME"] = "someone-else"

        page = self.client.get("/admin/settings")
        response = self.client.post(
            "/api/admin/transfer-risk",
            headers={"X-CSRF-Token": self.csrf_token},
            json={"amount_ratio_limit": 8},
        )

        self.assertEqual(page.status_code, 403)
        self.assertEqual(response.status_code, 403)
        with app.app_context():
            with closing(connect()) as connection:
                stored = connection.execute(
                    "SELECT setting_value FROM app_settings "
                    "WHERE setting_key = 'transfer_risk_ratio_limit'"
                ).fetchone()["setting_value"]
        self.assertEqual(stored, 5)

    def test_invalid_admin_risk_threshold_is_rejected(self) -> None:
        app.config["ADMIN_USERNAME"] = "sender"
        self._grant_admin_role(1)

        response = self.client.post(
            "/api/admin/transfer-risk",
            headers={"X-CSRF-Token": self.csrf_token},
            json={"amount_ratio_limit": 0},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Enter a whole-number threshold from 1 to 100.")

    def test_admin_threshold_controls_when_transfer_amount_is_flagged(self) -> None:
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET opening_balance_cents = 1_000 WHERE id = 1"
                )

            default_assessment = _transfer_risk(1, 6_000)
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE app_settings SET setting_value = 8 "
                    "WHERE setting_key = 'transfer_risk_ratio_limit'"
                )
            adjusted_assessment = _transfer_risk(1, 6_000)

        self.assertEqual(default_assessment["action"], "block")
        self.assertEqual(adjusted_assessment["action"], "allow")

    def test_database_error_mid_transfer_rolls_back_all_transfer_writes(self) -> None:
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    """
                    CREATE TRIGGER reject_ledger_write BEFORE INSERT ON ledger_entries
                    BEGIN
                        SELECT RAISE(ABORT, 'injected test failure');
                    END
                    """
                )

            with self.assertRaises(sqlite3.IntegrityError):
                _execute_transfer(
                    1,
                    {
                        "recipient": "recipient",
                        "amount": "25.00",
                        "reference": "rollback test",
                        "idempotency_key": "rollback-request-key-0001",
                    },
                )

        self.assertEqual(self._balances_and_transfer_counts(), ([100_000, 0], 0, 0))

    def test_password_hashing_uses_distinct_salts_and_verifies(self) -> None:
        with app.app_context():
            first_salt, first_hash = hash_password("Strong-test-password-42!")
            second_salt, second_hash = hash_password("Strong-test-password-42!")

        self.assertNotEqual(first_salt, second_salt)
        self.assertNotEqual(first_hash, second_hash)
        self.assertTrue(verify_password("Strong-test-password-42!", first_salt, first_hash))
        self.assertFalse(verify_password("incorrect-password", first_salt, first_hash))

    def test_password_sign_in_completes_without_requesting_payment_pin_again(self) -> None:
        password = "Strong-test-password-42!"
        self._trust_login_device()
        with app.app_context():
            password_salt, password_hash = hash_password(password)
            with closing(connect()) as connection:
                connection.execute(
                    """
                    UPDATE users SET password_salt = ?, password_hash = ?,
                        payment_pin_salt = NULL, payment_pin_hash = NULL
                    WHERE id = 1
                    """,
                    (password_salt, password_hash),
                )
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        password_response = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "sender",
                "password": password,
                "device_id": "device_identifier_123456",
            },
        )
        self.assertEqual(password_response.status_code, 200)
        self.assertEqual(password_response.get_json()["redirect"], "/dashboard")
        self.assertNotIn("payment_pin_required", password_response.get_json())
        with self.client.session_transaction() as browser_session:
            self.assertEqual(browser_session["user_id"], 1)
            self.assertIn("session_token", browser_session)
        with app.app_context():
            with closing(connect()) as connection:
                payment_pin_hash = connection.execute(
                    "SELECT payment_pin_hash FROM users WHERE id = 1"
                ).fetchone()["payment_pin_hash"]
        self.assertIsNone(payment_pin_hash)

    def test_authenticator_enrollment_returns_qr_and_hashed_recovery_codes(self) -> None:
        setup = self.client.post(
            "/api/mfa/setup",
            headers={"X-CSRF-Token": self.csrf_token},
            json={},
        )

        self.assertEqual(setup.status_code, 200)
        setup_data = setup.get_json()
        self.assertTrue(setup_data["qr_code"].startswith("data:image/png;base64,"))
        secret = setup_data["secret"]
        enabled = self.client.post(
            "/api/mfa/enable",
            headers={"X-CSRF-Token": self.csrf_token},
            json={"totp_code": pyotp.TOTP(secret).now()},
        )

        self.assertEqual(enabled.status_code, 200)
        recovery_codes = enabled.get_json()["recovery_codes"]
        self.assertEqual(len(recovery_codes), app.config["MFA_RECOVERY_CODE_COUNT"])
        self.assertEqual(len(set(recovery_codes)), len(recovery_codes))
        with app.app_context():
            with closing(connect()) as connection:
                user = connection.execute(
                    "SELECT mfa_secret_ciphertext, mfa_enabled FROM users WHERE id = 1"
                ).fetchone()
                stored_codes = [
                    row["code_hash"]
                    for row in connection.execute(
                        "SELECT code_hash FROM mfa_recovery_codes WHERE user_id = 1"
                    )
                ]
                chain = verify_audit_chain(connection)
        self.assertEqual(user["mfa_enabled"], 1)
        self.assertNotEqual(user["mfa_secret_ciphertext"], secret.encode())
        self.assertNotIn(recovery_codes[0], stored_codes)
        with app.app_context():
            self.assertIn(hash_recovery_code(recovery_codes[0]), stored_codes)
        self.assertTrue(chain["valid"])

    def test_enabled_mfa_is_required_during_login_and_blocks_totp_replay(self) -> None:
        password = "Strong-test-password-42!"
        secret = pyotp.random_base32()
        current_counter = int(time.time() // 30)
        with app.app_context():
            salt, digest = hash_password(password)
            from security import encrypt_sensitive_value

            with closing(connect()) as connection:
                connection.execute(
                    """
                    UPDATE users SET password_salt = ?, password_hash = ?,
                        mfa_secret_ciphertext = ?, mfa_enabled = 1,
                        last_mfa_counter = ?
                    WHERE id = 1
                    """,
                    (salt, digest, encrypt_sensitive_value(secret), current_counter - 1),
                )
        self._trust_login_device()
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        login_response = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "sender",
                "password": password,
                "device_id": "device_identifier_123456",
            },
        )
        challenge = login_response.get_json()
        self.assertEqual(login_response.status_code, 200)
        self.assertTrue(challenge["verification_required"])
        self.assertEqual(challenge["verification_method"], "totp")

        token = pyotp.TOTP(secret).now()
        verified = self.client.post(
            "/api/login/verify",
            headers={"X-CSRF-Token": csrf_token},
            json={"challenge_id": challenge["challenge_id"], "totp_code": token},
        )
        self.assertEqual(verified.status_code, 200)

        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]
        second_login = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "sender",
                "password": password,
                "device_id": "device_identifier_123456",
            },
        )
        second_challenge = second_login.get_json()
        replay = self.client.post(
            "/api/login/verify",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "challenge_id": second_challenge["challenge_id"],
                "totp_code": token,
            },
        )
        self.assertEqual(replay.status_code, 401)

    def test_high_value_transfer_requires_totp_and_consumes_recovery_code_once(self) -> None:
        secret = pyotp.random_base32()
        with app.app_context():
            from security import encrypt_sensitive_value

            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET mfa_secret_ciphertext = ?, mfa_enabled = 1 "
                    "WHERE id = 1",
                    (encrypt_sensitive_value(secret),),
                )
                connection.execute(
                    "INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at) "
                    "VALUES (1, ?, ?)",
                    (hash_recovery_code("ABCDEF0123456789"), int(time.time())),
                )

        no_totp = self._post_transfer(
            amount="1000.00",
            idempotency_key="high-value-transfer-key-01",
        )
        self.assertEqual(no_totp.status_code, 401)
        with app.app_context():
            with closing(connect()) as connection:
                changed = connection.execute(
                    "UPDATE users SET balance_cents = 150_000 WHERE id = 1"
                )
        self.assertEqual(changed.rowcount, 1)
        recovery = self.client.post(
            "/api/transfer",
            headers={"X-CSRF-Token": self.csrf_token},
            json={
                "recipient": "recipient",
                "amount": "1000.00",
                "reference": "high value",
                "payment_pin": "123456",
                "totp_code": "ABCDEF0123456789",
                "idempotency_key": "high-value-transfer-key-02",
            },
        )

        self.assertEqual(recovery.status_code, 200)
        replay = self.client.post(
            "/api/transfer",
            headers={"X-CSRF-Token": self.csrf_token},
            json={
                "recipient": "recipient",
                "amount": "1000.00",
                "reference": "replay recovery",
                "payment_pin": "123456",
                "totp_code": "ABCDEF0123456789",
                "idempotency_key": "high-value-transfer-key-03",
            },
        )
        self.assertEqual(replay.status_code, 401)
        with app.app_context():
            with closing(connect()) as connection:
                spent = connection.execute(
                    "SELECT used_at FROM mfa_recovery_codes WHERE user_id = 1"
                ).fetchone()["used_at"]
        self.assertIsNotNone(spent)

    def test_monthly_statement_is_private_in_memory_pdf_with_hmac(self) -> None:
        self._post_transfer(
            amount="25.00",
            idempotency_key="monthly-statement-transfer-001",
        )
        month = time.strftime("%Y-%m", time.gmtime())

        response = self.client.get(f"/statements/monthly?month={month}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertIn("attachment;", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["Cache-Control"], "private, no-store")
        self.assertEqual(len(response.headers["X-Statement-HMAC-SHA256"]), 64)
        self.assertTrue(response.data.startswith(b"%PDF"))

    def test_audit_chain_prevents_updates_and_detects_tampering(self) -> None:
        with app.app_context():
            with closing(connect()) as connection:
                append_audit_entry(
                    connection,
                    1,
                    "Test sensitive action",
                    {"field": "phone"},
                    int(time.time()),
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE audit_chain SET operation = 'tampered' WHERE id = 1"
                    )
                connection.execute("DROP TRIGGER prevent_audit_chain_update")
                connection.execute(
                    "UPDATE audit_chain SET operation = 'tampered' WHERE id = 1"
                )
                result = verify_audit_chain(connection)
        self.assertFalse(result["valid"])
        self.assertEqual(result["first_invalid_id"], 1)

    def test_medium_risk_login_requires_single_use_payment_pin_challenge(self) -> None:
        password = "Strong-test-password-42!"
        with app.app_context():
            salt, digest = hash_password(password)
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = 1",
                    (salt, digest),
                )
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        challenge_response = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "sender",
                "password": password,
                "device_id": "device_identifier_123456",
            },
        )

        challenge = challenge_response.get_json()
        self.assertEqual(challenge_response.status_code, 200)
        self.assertTrue(challenge["verification_required"])
        self.assertEqual(challenge["risk"]["level"], "MEDIUM")
        with self.client.session_transaction() as browser_session:
            self.assertNotIn("session_token", browser_session)

        wrong_pin = self.client.post(
            "/api/login/verify",
            headers={"X-CSRF-Token": csrf_token},
            json={"challenge_id": challenge["challenge_id"], "payment_pin": "654321"},
        )
        completed = self.client.post(
            "/api/login/verify",
            headers={"X-CSRF-Token": csrf_token},
            json={"challenge_id": challenge["challenge_id"], "payment_pin": "123456"},
        )
        replay = self.client.post(
            "/api/login/verify",
            headers={"X-CSRF-Token": csrf_token},
            json={"challenge_id": challenge["challenge_id"], "payment_pin": "123456"},
        )

        self.assertEqual(wrong_pin.status_code, 401)
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.get_json()["redirect"], "/dashboard")
        self.assertEqual(replay.status_code, 400)
        with app.app_context():
            with closing(connect()) as connection:
                risk_event = connection.execute(
                    "SELECT risk_level, action FROM risk_events "
                    "WHERE user_id = 1 AND event_type = 'login'"
                ).fetchone()
                challenge_count = connection.execute(
                    "SELECT COUNT(*) AS count FROM login_challenges"
                ).fetchone()["count"]
        self.assertEqual(risk_event["risk_level"], "MEDIUM")
        self.assertEqual(risk_event["action"], "require_pin")
        self.assertEqual(challenge_count, 0)

    def test_high_risk_login_is_blocked_and_logged(self) -> None:
        password = "Strong-test-password-42!"
        with app.app_context():
            salt, digest = hash_password(password)
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = 1",
                    (salt, digest),
                )
                connection.execute(
                    "INSERT INTO login_events (user_id, occurred_at, latitude, longitude) "
                    "VALUES (?, ?, ?, ?)",
                    (1, int(time.time()) - 600, 0.0, 0.0),
                )
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        response = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "sender",
                "password": password,
                "device_id": "new_device_identifier_12345",
                "latitude": 20,
                "longitude": 0,
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["risk"]["level"], "HIGH")
        with self.client.session_transaction() as browser_session:
            self.assertNotIn("session_token", browser_session)
        with app.app_context():
            with closing(connect()) as connection:
                event = connection.execute(
                    "SELECT risk_level, action, features_json FROM risk_events "
                    "WHERE user_id = 1 AND event_type = 'login'"
                ).fetchone()
        self.assertEqual(event["risk_level"], "HIGH")
        self.assertEqual(event["action"], "block")
        self.assertIn("physical_speed_kmh", event["features_json"])

    def test_three_consecutive_wrong_passwords_permanently_lock_account(self) -> None:
        password = "Strong-test-password-42!"
        with app.app_context():
            salt, digest = hash_password(password)
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = 1",
                    (salt, digest),
                )
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        responses = [
            self.client.post(
                "/api/login",
                headers={"X-CSRF-Token": csrf_token},
                json={
                    "username": "sender",
                    "password": "incorrect-password",
                    "device_id": "device_identifier_123456",
                },
            )
            for _ in range(3)
        ]

        self.assertEqual([response.status_code for response in responses], [401, 401, 423])
        with app.app_context():
            with closing(connect()) as connection:
                account = connection.execute(
                    "SELECT account_status, failed_login_attempts, account_locked_at "
                    "FROM users WHERE id = 1"
                ).fetchone()
        self.assertEqual(account["account_status"], "locked")
        self.assertEqual(account["failed_login_attempts"], 3)
        self.assertIsNotNone(account["account_locked_at"])
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET account_locked_at = 1, locked_until = 0 WHERE id = 1"
                )

        correct_password = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "sender",
                "password": password,
                "device_id": "device_identifier_123456",
            },
        )
        self.assertEqual(correct_password.status_code, 423)

    def test_rotating_ips_does_not_bypass_account_lockout_and_attempts_are_logged(self) -> None:
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        responses = []
        for index, ip_address in enumerate(("198.51.100.1", "198.51.100.2", "198.51.100.3")):
            responses.append(
                self.client.post(
                    "/api/login",
                    headers={"X-CSRF-Token": csrf_token},
                    environ_base={"REMOTE_ADDR": ip_address},
                    json={
                        "username": "sender",
                        "password": f"wrong-password-{index}",
                        "device_id": "device_identifier_123456",
                    },
                )
            )

        self.assertEqual([response.status_code for response in responses], [401, 401, 423])
        with app.app_context():
            with closing(connect()) as connection:
                attempts = connection.execute(
                    """
                    SELECT outcome, ip_hash FROM login_attempts
                    WHERE user_id = 1 AND username_hash = ?
                    ORDER BY id
                    """,
                    [
                        hmac.new(
                            app.config["SECRET_KEY"].encode(),
                            b"username:sender",
                            hashlib.sha256,
                        ).hexdigest()
                    ],
                ).fetchall()
                account = connection.execute(
                    "SELECT account_status FROM users WHERE id = 1"
                ).fetchone()
        self.assertEqual(len(attempts), 3)
        self.assertEqual(len({row["ip_hash"] for row in attempts}), 3)
        self.assertEqual(account["account_status"], "locked")

    def test_unknown_username_throttle_is_not_bypassed_by_changing_ip(self) -> None:
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        for ip_address in ("198.51.100.10", "198.51.100.11", "198.51.100.12"):
            response = self.client.post(
                "/api/login",
                headers={"X-CSRF-Token": csrf_token},
                environ_base={"REMOTE_ADDR": ip_address},
                json={
                    "username": "missing-account",
                    "password": "wrong-password",
                    "device_id": "device_identifier_123456",
                },
            )
        self.assertEqual(response.status_code, 401)

        throttled = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            environ_base={"REMOTE_ADDR": "198.51.100.13"},
            json={
                "username": "missing-account",
                "password": "wrong-password",
                "device_id": "device_identifier_123456",
            },
        )
        self.assertEqual(throttled.status_code, 429)

    def test_login_velocity_uses_five_minute_window(self) -> None:
        now = int(time.time())
        with app.app_context():
            with closing(connect()) as connection:
                connection.executemany(
                    "INSERT INTO login_events (user_id, occurred_at) VALUES (1, ?)",
                    ((now - 360,), (now - 240,)),
                )
            features = _risk_features_for_login(
                1,
                hash_token("device_identifier_123456"),
                None,
                None,
            )
        self.assertEqual(features.login_velocity, 2.0)

    def test_correct_password_resets_consecutive_failure_count(self) -> None:
        password = "Strong-test-password-42!"
        self._trust_login_device()
        with app.app_context():
            salt, digest = hash_password(password)
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = 1",
                    (salt, digest),
                )
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        for _ in range(2):
            self.client.post(
                "/api/login",
                headers={"X-CSRF-Token": csrf_token},
                json={
                    "username": "sender",
                    "password": "incorrect-password",
                    "device_id": "device_identifier_123456",
                },
            )
        successful_login = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "sender",
                "password": password,
                "device_id": "device_identifier_123456",
            },
        )

        self.assertEqual(successful_login.status_code, 200)
        with app.app_context():
            with closing(connect()) as connection:
                account = connection.execute(
                    "SELECT account_status, failed_login_attempts FROM users WHERE id = 1"
                ).fetchone()
        self.assertEqual(account["account_status"], "active")
        self.assertEqual(account["failed_login_attempts"], 0)

    def test_admin_can_view_and_unlock_locked_account(self) -> None:
        app.config["ADMIN_USERNAME"] = "recipient"
        self._grant_admin_role(2)
        self._authenticate_as(2)
        password = "Strong-test-password-42!"
        with app.app_context():
            password_salt, password_hash = hash_password(password)
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET password_salt = ?, password_hash = ? WHERE id = 1",
                    (password_salt, password_hash),
                )
                connection.execute(
                    """
                    UPDATE users SET account_status = 'locked',
                        failed_login_attempts = 3, account_locked_at = ?
                    WHERE id = 1
                    """,
                    (int(time.time()),),
                )
                connection.execute("UPDATE sessions SET revoked = 1 WHERE user_id = 1")

        page = self.client.get("/admin/settings")
        unlock_response = self.client.post(
            "/api/admin/accounts/1/unlock",
            headers={"X-CSRF-Token": self.csrf_token},
            json={},
        )

        self.assertEqual(page.status_code, 200)
        self.assertIn(b"sender", page.data)
        self.assertIn(b"Unlock", page.data)
        self.assertEqual(unlock_response.status_code, 200)
        with app.app_context():
            with closing(connect()) as connection:
                account = connection.execute(
                    "SELECT account_status, failed_login_attempts, account_locked_at "
                    "FROM users WHERE id = 1"
                ).fetchone()
        self.assertEqual(account["account_status"], "active")
        self.assertEqual(account["failed_login_attempts"], 0)
        self.assertIsNone(account["account_locked_at"])
        login_response = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": self.csrf_token},
            json={
                "username": "sender",
                "password": password,
                "device_id": "device_identifier_123456",
            },
        )
        self.assertEqual(login_response.status_code, 200)

    def test_non_admin_cannot_unlock_accounts(self) -> None:
        app.config["ADMIN_USERNAME"] = "another-user"
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE users SET account_status = 'locked' WHERE id = 2"
                )

        response = self.client.post(
            "/api/admin/accounts/2/unlock",
            headers={"X-CSRF-Token": self.csrf_token},
            json={},
        )

        self.assertEqual(response.status_code, 403)
        with app.app_context():
            with closing(connect()) as connection:
                status = connection.execute(
                    "SELECT account_status FROM users WHERE id = 2"
                ).fetchone()["account_status"]
        self.assertEqual(status, "locked")

    def test_dashboard_header_links_short_name_to_profile(self) -> None:
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'class="user-chip" href="/profile"', response.data)
        self.assertIn(b'class="uc-name">Test</span>', response.data)
        self.assertIn(b"Welcome back, Test", response.data)
        self.assertIn(b"Secure session active", response.data)
        self.assertIn(b"data-receipt-back>Go back</button>", response.data)
        self.assertIn(b"Download receipt", response.data)
        self.assertNotIn(b"Print receipt", response.data)
        self.assertNotIn(b"Financial services disclosure", response.data)
        self.assertNotIn(b"Balances and transfers are application records only", response.data)
        self.assertNotIn(b">Profile settings</a>", response.data)

    def test_profile_does_not_offer_payment_password_recreation(self) -> None:
        response = self.client.get("/profile")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"profile-pin-form", response.data)
        self.assertNotIn(b"Update Payment Password", response.data)
        self.assertEqual(
            self.client.post(
                "/api/profile/payment-pin",
                headers={"X-CSRF-Token": self.csrf_token},
                json={},
            ).status_code,
            404,
        )

    def test_transfer_recipient_sql_like_input_is_treated_as_literal(self) -> None:
        response = self.client.post(
            "/api/transfer",
            headers={"X-CSRF-Token": self.csrf_token},
            json={
                "recipient": "' OR 1=1 --",
                "amount": "25.00",
                "reference": "literal input test",
                "payment_pin": "123456",
                "idempotency_key": "sql-input-request-0001",
            },
        )

        self.assertEqual(response.status_code, 404)
        self.assertEqual(self._balances_and_transfer_counts(), ([100_000, 0], 0, 0))

    def test_login_treats_sql_like_username_as_literal_input(self) -> None:
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        self.client.get("/login")
        with self.client.session_transaction() as browser_session:
            csrf_token = browser_session["csrf_token"]

        response = self.client.post(
            "/api/login",
            headers={"X-CSRF-Token": csrf_token},
            json={
                "username": "' OR 1=1 --",
                "password": "unmatched-password",
                "device_id": "device_identifier_123456",
            },
        )

        self.assertEqual(response.status_code, 401)
        with app.app_context():
            with closing(connect()) as connection:
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                    2,
                )

    def test_revoked_database_session_cannot_access_dashboard(self) -> None:
        with app.app_context():
            with closing(connect()) as connection:
                connection.execute(
                    "UPDATE sessions SET revoked = 1 WHERE token_hash = ?",
                    (hash_token(self.session_token),),
                )

        response = self.client.get("/dashboard", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request.path, "/login")

    def test_protected_dashboard_rejects_anonymous_request(self) -> None:
        with self.client.session_transaction() as browser_session:
            browser_session.clear()

        response = self.client.get("/dashboard", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request.path, "/login")

    def test_transaction_history_is_authenticated_and_account_scoped(self) -> None:
        transfer = self._post_transfer()
        self.assertEqual(transfer.status_code, 200)
        self._authenticate_as(2)

        response = self.client.get("/transactions")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Transaction history", response.data)
        self.assertIn(b"sender", response.data)
        self.assertIn(b"Completed", response.data)
        self.assertIn(b"+$25.00", response.data)
        self.assertNotIn(b"1000000001", response.data)

    def test_transaction_history_rejects_anonymous_users_and_invalid_pages(self) -> None:
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        anonymous = self.client.get("/transactions")
        self.assertEqual(anonymous.status_code, 302)
        self.assertEqual(anonymous.headers["Location"], "/auth")

        with self.client.session_transaction() as browser_session:
            browser_session["user_id"] = 1
            browser_session["session_token"] = self.session_token
        invalid_page = self.client.get("/transactions?page=not-a-page")
        self.assertEqual(invalid_page.status_code, 400)

    def test_security_headers_are_added_to_responses(self) -> None:
        with self.client.session_transaction() as browser_session:
            browser_session.clear()
        response = self.client.get("/")

        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            response.headers["Referrer-Policy"],
            "strict-origin-when-cross-origin",
        )

    def test_unknown_application_environment_fails_fast(self) -> None:
        environment = os.environ.copy()
        environment["APP_ENV"] = "prod"
        result = subprocess.run(
            [sys.executable, "-c", "import config"],
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APP_ENV must be either", result.stderr)

    def test_legacy_database_migration_adds_transfer_idempotency_column(self) -> None:
        legacy_path = str(Path(self.temporary_directory.name) / "legacy.sqlite3")
        previous_database_path = app.config["DATABASE_PATH"]
        app.config["DATABASE_PATH"] = legacy_path
        try:
            with closing(sqlite3.connect(legacy_path)) as connection:
                connection.executescript(
                    SCHEMA.replace("    idempotency_key TEXT,\n", "")
                    .replace("    reference_ciphertext BLOB,\n", "")
                    .replace(
                        "    can_transfer INTEGER NOT NULL DEFAULT 1 CHECK (can_transfer IN (0, 1)),\n",
                        "",
                    )
                    .replace("    role TEXT NOT NULL DEFAULT 'customer',\n", "")
                    .replace("    failed_login_attempts INTEGER NOT NULL DEFAULT 0,\n", "")
                    .replace("    locked_until INTEGER NOT NULL DEFAULT 0,\n", "")
                )
            with app.app_context():
                initialize_database()
                with closing(connect()) as connection:
                    columns = {
                        row["name"]
                        for row in connection.execute("PRAGMA table_info(transfers)")
                    }
                    user_columns = {
                        row["name"]
                        for row in connection.execute("PRAGMA table_info(users)")
                    }
                    challenge_columns = {
                        row["name"]
                        for row in connection.execute(
                            "PRAGMA table_info(login_challenges)"
                        )
                    }
            self.assertIn("idempotency_key", columns)
            self.assertIn("reference_ciphertext", columns)
            self.assertIn("can_transfer", user_columns)
            self.assertIn("role", user_columns)
            self.assertIn("failed_login_attempts", user_columns)
            self.assertIn("locked_until", user_columns)
            self.assertIn("risk_level", challenge_columns)
            self.assertIn("risk_score", challenge_columns)
        finally:
            app.config["DATABASE_PATH"] = previous_database_path

    def test_risk_graph_and_avl_helpers(self) -> None:
        engine = RiskEngine()
        self.assertEqual(engine.assess(RiskFeatures())["action"], "allow")
        self.assertEqual(
            engine.assess(RiskFeatures(new_device=1))["action"],
            "require_pin",
        )
        self.assertEqual(
            engine.assess(RiskFeatures(amount_ratio=5.1))["action"],
            "block",
        )
        self.assertEqual(
            engine.assess(RiskFeatures(amount_ratio=5.1), amount_ratio_limit=6)["action"],
            "allow",
        )
        self.assertEqual(
            engine.assess(
                RiskFeatures(
                    distance_km=1_200,
                    interval_hours=1,
                    physical_speed_kmh=1_200,
                    login_velocity=2,
                ),
                block_on_model_consensus=True,
            )["action"],
            "block",
        )

        graph = AccessGraph.from_sequence(["Login", "Database", "Admin", "Files"])
        self.assertEqual(graph.bfs("Login"), ["Login", "Database", "Admin", "Files"])
        self.assertEqual(
            graph.suspicious_paths(),
            [["Login", "Database", "Admin", "Files"]],
        )
        denied_admin_graph = AccessGraph.from_sequence(
            ["Login", "Database", "Admin denied"]
        )
        self.assertEqual(
            denied_admin_graph.suspicious_paths(),
            [["Login", "Database", "Admin denied"]],
        )

        tree = AVLTree()
        for key in range(1, 1_001):
            tree.insert(key, key * 100)
        self.assertEqual(tree.search(513), 51_300)
        self.assertEqual(tree.size, 1_000)
        self.assertLessEqual(tree.height, 14)


if __name__ == "__main__":
    unittest.main()
