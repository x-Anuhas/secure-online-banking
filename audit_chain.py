"""Tamper-evident, append-only audit-chain helpers."""

import hashlib
import hmac
import json
import sqlite3

from flask import current_app


GENESIS_HASH = "0" * 64


def _signature(payload: bytes) -> str:
    key = current_app.config["SECRET_KEY"].encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def append_audit_entry(
    connection: sqlite3.Connection,
    user_id: int,
    operation: str,
    details: dict[str, object],
    occurred_at: int,
) -> str:
    """Append one signed hash-chain entry inside the caller's transaction."""
    details_json = json.dumps(details, sort_keys=True, separators=(",", ":"))
    previous = connection.execute(
        "SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["entry_hash"] if previous else GENESIS_HASH
    canonical_entry = json.dumps(
        {
            "user_id": user_id,
            "operation": operation,
            "details_json": details_json,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    entry_hash = _signature(canonical_entry)
    connection.execute(
        """
        INSERT INTO audit_chain
            (user_id, operation, details_json, occurred_at, previous_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            operation,
            details_json,
            occurred_at,
            previous_hash,
            entry_hash,
        ),
    )
    return entry_hash


def verify_audit_chain(connection: sqlite3.Connection) -> dict[str, object]:
    """Verify link continuity and HMACs for the complete chain in sequence."""
    entries = connection.execute(
        """
        SELECT id, user_id, operation, details_json, occurred_at,
               previous_hash, entry_hash
        FROM audit_chain ORDER BY id
        """
    ).fetchall()
    expected_previous = GENESIS_HASH
    for entry in entries:
        if not hmac.compare_digest(entry["previous_hash"], expected_previous):
            return {
                "valid": False,
                "entries_checked": entry["id"] - 1,
                "first_invalid_id": entry["id"],
            }
        canonical_entry = json.dumps(
            {
                "user_id": entry["user_id"],
                "operation": entry["operation"],
                "details_json": entry["details_json"],
                "occurred_at": entry["occurred_at"],
                "previous_hash": entry["previous_hash"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        actual_hash = _signature(canonical_entry)
        if not hmac.compare_digest(entry["entry_hash"], actual_hash):
            return {
                "valid": False,
                "entries_checked": entry["id"] - 1,
                "first_invalid_id": entry["id"],
            }
        expected_previous = entry["entry_hash"]
    return {"valid": True, "entries_checked": len(entries), "first_invalid_id": None}
