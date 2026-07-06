from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "compliance_agent.db"
_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'paste',
    source TEXT NOT NULL DEFAULT 'pasted-code',
    scanned_files INTEGER NOT NULL DEFAULT 1,
    total_violations INTEGER NOT NULL DEFAULT 0,
    critical INTEGER NOT NULL DEFAULT 0,
    medium INTEGER NOT NULL DEFAULT 0,
    low INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
"""


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path | None = None) -> None:
    with _lock:
        conn = get_connection(db_path)
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def save_report_row(report: dict[str, Any], db_path: Path | None = None) -> None:
    init_db(db_path)
    with _lock:
        conn = get_connection(db_path)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO reports (
                    report_id, timestamp, scan_type, source, scanned_files,
                    total_violations, critical, medium, low, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report["report_id"],
                    report["timestamp"],
                    report.get("scan_type", "paste"),
                    report.get("source", "pasted-code"),
                    report.get("scanned_files", 1),
                    report.get("total_violations", 0),
                    report.get("critical", 0),
                    report.get("medium", 0),
                    report.get("low", 0),
                    json.dumps(report),
                ),
            )
            conn.commit()
        finally:
            conn.close()


def load_report_row(report_id: str, db_path: Path | None = None) -> dict[str, Any]:
    init_db(db_path)
    with _lock:
        conn = get_connection(db_path)
        try:
            row = conn.execute(
                "SELECT payload_json FROM reports WHERE report_id = ?",
                (report_id,),
            ).fetchone()
            if not row:
                raise FileNotFoundError(report_id)
            return json.loads(row["payload_json"])
        finally:
            conn.close()


def list_report_summaries(limit: int = 10, db_path: Path | None = None) -> list[dict[str, Any]]:
    init_db(db_path)
    with _lock:
        conn = get_connection(db_path)
        try:
            rows = conn.execute(
                """
                SELECT report_id, timestamp, total_violations, critical, medium, low,
                       scan_type, source
                FROM reports
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


def load_metrics(db_path: Path | None = None) -> dict[str, Any]:
    init_db(db_path)
    default = {
        "total_scans": 0,
        "total_violations": 0,
        "violations_by_severity": {"critical": 0, "medium": 0, "low": 0},
        "total_scan_time_ms": 0,
        "step_times_ms": {"semgrep": 0, "opa": 0, "ai_summary": 0},
        "step_counts": {"semgrep": 0, "opa": 0, "ai_summary": 0},
    }
    with _lock:
        conn = get_connection(db_path)
        try:
            row = conn.execute(
                "SELECT value_json FROM metrics WHERE key = 'aggregate'"
            ).fetchone()
            if not row:
                return default
            data = json.loads(row["value_json"])
            default.update(data)
            return default
        finally:
            conn.close()


def save_metrics(metrics: dict[str, Any], db_path: Path | None = None) -> None:
    init_db(db_path)
    with _lock:
        conn = get_connection(db_path)
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO metrics (key, value_json)
                VALUES ('aggregate', ?)
                """,
                (json.dumps(metrics),),
            )
            conn.commit()
        finally:
            conn.close()
