"""
CyberSage Storage & Session Isolation Engine.

Provides persistent, thread-safe, and session-isolated storage for security scans
and remediation verification audit trails using SQLite.
"""

import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "cyber_sage.db")


def _get_connection() -> sqlite3.Connection:
    """Creates a connection to the SQLite database and ensures schema exists."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_session():
    """Context manager that ensures the SQLite connection is committed and closed."""
    conn = _get_connection()
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    """Initializes the database schema if not already present."""
    with db_session() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                scan_mode TEXT NOT NULL,
                scan_source TEXT NOT NULL,
                target_host TEXT NOT NULL,
                created_at TEXT NOT NULL,
                score INTEGER,
                score_label TEXT NOT NULL,
                total_checks INTEGER NOT NULL,
                safe_count INTEGER NOT NULL,
                warning_count INTEGER NOT NULL,
                unknown_count INTEGER NOT NULL,
                not_applicable_count INTEGER NOT NULL,
                is_complete INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS verifications (
                verification_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                control_name TEXT NOT NULL,
                previous_status TEXT NOT NULL,
                new_status TEXT NOT NULL,
                outcome TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_session ON scans(session_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_verifications_scan ON verifications(scan_id)")
        conn.commit()


def save_scan(report: Dict[str, Any], session_id: str) -> str:
    """
    Persists a new scan record with a unique UUID and session association.

    Args:
        report: Complete scan report dictionary.
        session_id: Flask session identifier for user isolation.

    Returns:
        The generated unique scan_id.
    """
    init_db()
    scan_id = report.get("scan_id") or str(uuid.uuid4())
    report["scan_id"] = scan_id
    report["session_id"] = session_id

    created_at = report.get("scanned_at") or datetime.now(timezone.utc).isoformat()
    scan_mode = report.get("scan_mode", "deep")
    scan_source = report.get("scan_source", "local_host")
    target_host = report.get("target_host", "Unknown Host")
    score = report.get("hygiene_percentage")
    score_label = report.get("score_label", "Security Score")
    total_checks = int(report.get("total_checks", 0))
    safe_count = int(report.get("safe_count", 0))
    warning_count = int(report.get("warning_count", 0))
    unknown_count = int(report.get("unknown_count", 0))
    na_count = int(report.get("not_applicable_count", 0))
    is_complete = 1 if report.get("is_complete", True) else 0
    report_json = json.dumps(report, ensure_ascii=False)

    with db_session() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (
                scan_id, session_id, scan_mode, scan_source, target_host,
                created_at, score, score_label, total_checks, safe_count,
                warning_count, unknown_count, not_applicable_count, is_complete,
                report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id, session_id, scan_mode, scan_source, target_host,
                created_at, score, score_label, total_checks, safe_count,
                warning_count, unknown_count, na_count, is_complete, report_json
            )
        )
        conn.commit()

    logger.info("Saved scan %s (source: %s, score: %s) for session %s", scan_id, scan_source, score, session_id)
    return scan_id


def get_scan(scan_id: str, session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves a scan report by its scan_id, optionally validating session ownership.
    """
    init_db()
    query = "SELECT report_json FROM scans WHERE scan_id = ?"
    params: List[Any] = [scan_id]
    if session_id:
        query += " AND session_id = ?"
        params.append(session_id)

    with db_session() as conn:
        row = conn.execute(query, params).fetchone()
        if row:
            try:
                return json.loads(row["report_json"])
            except Exception as e:
                logger.error("Failed to parse stored scan JSON for %s: %s", scan_id, e)
    return None


def get_latest_scan_for_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves the most recent scan report generated or accessed by this session."""
    init_db()
    with db_session() as conn:
        row = conn.execute(
            "SELECT report_json FROM scans WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
            (session_id,)
        ).fetchone()
        if row:
            try:
                return json.loads(row["report_json"])
            except Exception as e:
                logger.error("Failed to parse latest session scan JSON: %s", e)
    return None


def update_scan(report: Dict[str, Any], session_id: Optional[str] = None) -> bool:
    """Updates an existing scan record with re-evaluated findings or score."""
    scan_id = report.get("scan_id")
    if not scan_id:
        return False

    init_db()
    score = report.get("hygiene_percentage")
    score_label = report.get("score_label", "Security Score")
    safe_count = int(report.get("safe_count", 0))
    warning_count = int(report.get("warning_count", 0))
    unknown_count = int(report.get("unknown_count", 0))
    na_count = int(report.get("not_applicable_count", 0))
    is_complete = 1 if report.get("is_complete", True) else 0
    report_json = json.dumps(report, ensure_ascii=False)

    query = """
        UPDATE scans SET
            score = ?, score_label = ?, safe_count = ?, warning_count = ?,
            unknown_count = ?, not_applicable_count = ?, is_complete = ?,
            report_json = ?
        WHERE scan_id = ?
    """
    params: List[Any] = [
        score, score_label, safe_count, warning_count,
        unknown_count, na_count, is_complete, report_json, scan_id
    ]
    if session_id:
        query += " AND session_id = ?"
        params.append(session_id)

    with db_session() as conn:
        cursor = conn.execute(query, params)
        conn.commit()
        return cursor.rowcount > 0


def record_verification(
    scan_id: str,
    control_id: str,
    control_name: str,
    previous_status: str,
    new_status: str,
    outcome: str,
    details: str = ""
) -> str:
    """
    Records an immutable verification audit log entry.
    """
    init_db()
    verification_id = str(uuid.uuid4())
    verified_at = datetime.now(timezone.utc).isoformat()

    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO verifications (
                verification_id, scan_id, control_id, control_name,
                previous_status, new_status, outcome, verified_at, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verification_id, scan_id, control_id, control_name,
                previous_status, new_status, outcome, verified_at, details
            )
        )
        conn.commit()
    return verification_id


def get_verifications_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    """Retrieves all verification log records for a given scan."""
    init_db()
    with db_session() as conn:
        rows = conn.execute(
            "SELECT * FROM verifications WHERE scan_id = ? ORDER BY verified_at ASC",
            (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]
