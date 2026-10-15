"""Persistence for scans and their findings.

A thin SQLite layer, not an ORM: the dashboard needs scan history and the ability
to re-open a finding to verify or patch it, which is a handful of queries. The
canonical finding shape lives in crypten.findings; this stores a flattened copy
plus the verification and remediation state the UI mutates.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "crypten.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target_path TEXT NOT NULL,
    target_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    scanners_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cwe_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    priority REAL NOT NULL,
    priority_reasons TEXT NOT NULL,
    evidence TEXT NOT NULL,
    scanners TEXT NOT NULL,
    in_scope INTEGER NOT NULL,
    verification TEXT NOT NULL DEFAULT 'UNVERIFIED',
    verification_summary TEXT DEFAULT '',
    verification_method TEXT DEFAULT '',
    verification_details TEXT DEFAULT '{}',
    remediation TEXT NOT NULL DEFAULT 'OPEN'
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init() -> None:
    with connect() as conn:
        conn.executescript(_SCHEMA)


def save_scan(result, score_of) -> str:
    scan_id = str(uuid.uuid4())
    with connect() as conn:
        conn.execute(
            "INSERT INTO scans (id, target_path, target_name, created_at, scanners_json) VALUES (?,?,?,?,?)",
            (
                scan_id,
                str(result.target.root),
                result.target.name,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                json.dumps([{"name": s.name, "ran": s.ran, "note": s.note} for s in result.scanners]),
            ),
        )
        from crypten.risk import score as score_fn

        for finding in result.findings:
            s = score_fn(finding)
            conn.execute(
                """INSERT INTO findings
                   (id, scan_id, cwe_id, rule_id, title, file_path, line, end_line,
                    severity, confidence, priority, priority_reasons, evidence, scanners,
                    in_scope, verification, remediation)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()), scan_id, finding.cwe_id, finding.rule_id, finding.title,
                    finding.file_path, finding.line, finding.end_line, finding.severity,
                    finding.confidence, s.value, s.explain(), finding.evidence,
                    "+".join(sorted(finding.corroborated_by)), int(finding.in_scope),
                    finding.verification, finding.remediation,
                ),
            )
    return scan_id


def list_scans() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """SELECT s.*,
                      (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS total,
                      (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity='CRITICAL') AS critical
               FROM scans s ORDER BY created_at DESC"""
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: str) -> dict | None:
    with connect() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan is None:
            return None
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY priority DESC", (scan_id,)
        ).fetchall()
    return {"scan": dict(scan), "findings": [dict(f) for f in findings]}


def get_finding(finding_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    return dict(row) if row else None


def update_verification(finding_id: str, outcome) -> None:
    with connect() as conn:
        conn.execute(
            """UPDATE findings SET verification=?, verification_summary=?,
               verification_method=?, verification_details=? WHERE id=?""",
            (outcome.result, outcome.summary, outcome.method, json.dumps(outcome.details), finding_id),
        )


def update_remediation(finding_id: str, status: str) -> None:
    with connect() as conn:
        conn.execute("UPDATE findings SET remediation=? WHERE id=?", (status, finding_id))
