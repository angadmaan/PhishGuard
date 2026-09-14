import json
import sqlite3
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

DB_PATH = "phishguard.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema and seeds default developer key."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        domain TEXT NOT NULL,
        verdict TEXT NOT NULL,
        total_score INTEGER NOT NULL,
        max_score INTEGER NOT NULL,
        risk_percentage REAL NOT NULL,
        flags_count INTEGER NOT NULL,
        checks_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS community_reports (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL,
        report_type TEXT NOT NULL,
        comment TEXT,
        created_at TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        key TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        rate_limit TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    # Seed demo developer API key
    cursor.execute("SELECT key FROM api_keys WHERE key = 'pg_live_demo_key_2026'")
    if not cursor.fetchone():
        cursor.execute("""
        INSERT INTO api_keys (key, name, rate_limit, created_at)
        VALUES (?, ?, ?, ?)
        """, (
            "pg_live_demo_key_2026",
            "Demo Developer Key",
            "120 per minute",
            datetime.now(timezone.utc).isoformat()
        ))

    conn.commit()
    conn.close()

def save_scan(result: dict) -> str:
    """Saves a scan result and returns a unique incident ID."""
    incident_id = "PG-" + uuid.uuid4().hex[:8].upper()
    url = result.get("url", "")
    try:
        domain = urlparse(url).hostname or url
    except Exception:
        domain = url

    flags_count = sum(1 for c in result.get("checks", []) if c.get("result") != "PASS")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO scans (
        id, url, domain, verdict, total_score, max_score,
        risk_percentage, flags_count, checks_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident_id,
        url,
        domain,
        result.get("verdict", "Unknown"),
        result.get("total_score", 0),
        result.get("max_score", 200),
        result.get("risk_percentage", 0.0),
        flags_count,
        json.dumps(result.get("checks", [])),
        now_iso
    ))
    conn.commit()
    conn.close()
    return incident_id

def get_scan(scan_id: str):
    """Retrieves a single scan by incident ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    data = dict(row)
    data["checks"] = json.loads(data["checks_json"])
    return data

def get_recent_scans(limit=25):
    """Retrieves the latest scans for the community live feed."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, url, domain, verdict, total_score, max_score, risk_percentage, flags_count, created_at
    FROM scans
    ORDER BY created_at DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_threat_stats():
    """Aggregates global threat telemetry for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'Dangerous'")
    dangerous_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'Suspicious'")
    suspicious_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE verdict = 'Safe'")
    safe_count = cursor.fetchone()[0]

    cursor.execute("""
    SELECT domain, COUNT(*) as count
    FROM scans
    WHERE verdict IN ('Dangerous', 'Suspicious')
    GROUP BY domain
    ORDER BY count DESC
    LIMIT 5
    """)
    top_threat_domains = [dict(r) for r in cursor.fetchall()]

    conn.close()

    safe_rate = round((safe_count / total_scans * 100), 1) if total_scans > 0 else 100.0

    return {
        "total_scans": total_scans,
        "dangerous_count": dangerous_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "safe_rate": safe_rate,
        "top_threat_domains": top_threat_domains
    }

def add_community_report(url: str, report_type: str, comment: str) -> str:
    """Stores a user-submitted threat report or false positive."""
    report_id = "RPT-" + uuid.uuid4().hex[:8].upper()
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO community_reports (id, url, report_type, comment, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (report_id, url, report_type, comment, now_iso))
    conn.commit()
    conn.close()
    return report_id

def get_community_reports(limit: int = 50):
    """Retrieves recent community threat and false positive submissions."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, url, report_type, comment, created_at
    FROM community_reports
    ORDER BY created_at DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def is_valid_api_key(api_key: str) -> bool:
    """Validates whether a developer API key exists."""
    if not api_key:
        return False
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key FROM api_keys WHERE key = ?", (api_key,))
    row = cursor.fetchone()
    conn.close()
    return row is not None

# Initialize on import
init_db()
