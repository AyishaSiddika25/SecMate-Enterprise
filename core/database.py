"""
core/database.py

SQLite persistence layer for SecMate assessment records.

Design notes:
- One table (`assessments`) stores each assessment run.
- Complex/nested data (test cases, vapt findings) is stored as JSON text
  in TEXT columns and decoded back into Python objects on read.
- All functions open a short-lived connection per call (safe for
  Streamlit's rerun model) rather than holding a global connection open.
"""

import sqlite3
import json
import os
from contextlib import contextmanager

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "secmate.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id       TEXT PRIMARY KEY,
    target               TEXT NOT NULL,
    assessment_type      TEXT NOT NULL,
    intensity            TEXT NOT NULL,
    overall_verdict       TEXT,
    test_case_count       INTEGER DEFAULT 0,
    defended_count         INTEGER DEFAULT 0,
    review_required_count  INTEGER DEFAULT 0,
    vapt_indicator_count   INTEGER DEFAULT 0,
    test_cases            TEXT,
    vapt_findings         TEXT,
    evidence_input        TEXT,
    review_status         TEXT DEFAULT 'Pending Review',
    review_notes          TEXT DEFAULT '',
    status                TEXT DEFAULT 'Completed',
    created_at            TEXT NOT NULL
);
"""


class DatabaseError(Exception):
    """Raised when a database operation fails, wrapping the underlying error."""
    pass


@contextmanager
def get_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Create the assessments table if it does not already exist. Safe to call repeatedly."""
    try:
        with get_connection() as conn:
            conn.execute(SCHEMA)
            conn.commit()
    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to initialize database: {e}") from e


def save_assessment(record: dict):
    """
    Persist a new assessment record.
    `record` is expected to already match the engine's output schema
    (see core/engine.py: run_assessment).
    """
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO assessments (
                    assessment_id, target, assessment_type, intensity,
                    overall_verdict, test_case_count, defended_count,
                    review_required_count, vapt_indicator_count,
                    test_cases, vapt_findings, evidence_input,
                    review_status, review_notes, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record["assessment_id"],
                    record["target"],
                    record["assessment_type"],
                    record["intensity"],
                    record.get("overall_verdict", "Unknown"),
                    record.get("test_case_count", 0),
                    record.get("defended_count", 0),
                    record.get("review_required_count", 0),
                    record.get("vapt_indicator_count", 0),
                    json.dumps(record.get("test_cases", [])),
                    json.dumps(record.get("vapt_findings", [])),
                    record.get("evidence_input", ""),
                    record.get("review_status", "Pending Review"),
                    record.get("review_notes", ""),
                    record.get("status", "Completed"),
                    record["created_at"],
                ),
            )
            conn.commit()
    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to save assessment: {e}") from e


def _row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    try:
        d["test_cases"] = json.loads(d.get("test_cases") or "[]")
    except (json.JSONDecodeError, TypeError):
        d["test_cases"] = []
    try:
        d["vapt_findings"] = json.loads(d.get("vapt_findings") or "[]")
    except (json.JSONDecodeError, TypeError):
        d["vapt_findings"] = []
    return d


def get_all_assessments(order_desc: bool = True) -> list:
    try:
        with get_connection() as conn:
            order = "DESC" if order_desc else "ASC"
            rows = conn.execute(f"SELECT * FROM assessments ORDER BY created_at {order}").fetchall()
            return [_row_to_dict(r) for r in rows]
    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to load assessments: {e}") from e


def get_assessment_by_id(assessment_id: str):
    try:
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM assessments WHERE assessment_id = ?", (assessment_id,)
            ).fetchone()
            return _row_to_dict(row) if row else None
    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to fetch assessment {assessment_id}: {e}") from e


def update_review(assessment_id: str, review_status: str = None, review_notes: str = None):
    """Update analyst review status and/or notes for a single assessment. Persists to disk immediately."""
    if review_status is None and review_notes is None:
        return
    try:
        with get_connection() as conn:
            if review_status is not None and review_notes is not None:
                conn.execute(
                    "UPDATE assessments SET review_status = ?, review_notes = ? WHERE assessment_id = ?",
                    (review_status, review_notes, assessment_id),
                )
            elif review_status is not None:
                conn.execute(
                    "UPDATE assessments SET review_status = ? WHERE assessment_id = ?",
                    (review_status, assessment_id),
                )
            else:
                conn.execute(
                    "UPDATE assessments SET review_notes = ? WHERE assessment_id = ?",
                    (review_notes, assessment_id),
                )
            conn.commit()
    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to update review for {assessment_id}: {e}") from e


def delete_assessment(assessment_id: str):
    try:
        with get_connection() as conn:
            cur = conn.execute("DELETE FROM assessments WHERE assessment_id = ?", (assessment_id,))
            conn.commit()
            return cur.rowcount > 0
    except sqlite3.Error as e:
        raise DatabaseError(f"Failed to delete assessment {assessment_id}: {e}") from e


def search_assessments(query: str = "", assessment_type: str = "All", review_status: str = "All") -> list:
    """Filter in Python after fetching — dataset is expected to stay small for a local prototype."""
    records = get_all_assessments()
    q = (query or "").strip().lower()
    out = []
    for r in records:
        if q and q not in r["assessment_id"].lower() and q not in r["target"].lower():
            continue
        if assessment_type != "All" and r["assessment_type"] != assessment_type:
            continue
        if review_status != "All" and r["review_status"] != review_status:
            continue
        out.append(r)
    return out


def get_metrics() -> dict:
    """Aggregate dashboard metrics computed from actual stored records — never hardcoded."""
    records = get_all_assessments()
    total = len(records)
    completed = sum(1 for r in records if r["status"] == "Completed")
    in_progress = sum(1 for r in records if r["status"] != "Completed")
    vapt_indicators = sum(r.get("vapt_indicator_count", 0) for r in records)
    return {
        "total_assessments": total,
        "completed": completed,
        "in_progress": in_progress,
        "vapt_indicators": vapt_indicators,
    }
