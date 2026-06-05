import sqlite3
import os
from black_sentinel.schemas.models import Finding, HoneycombAlert

DB_PATH = "events.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            event_id TEXT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity TEXT,
            event_type TEXT NOT NULL,
            source TEXT,
            raw_extract TEXT,
            vault_ref TEXT,
            file_path TEXT NOT NULL,
            detector TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            masked_value TEXT NOT NULL,
            context TEXT,
            confidence REAL,
            line_number INTEGER,
            validated BOOLEAN,
            vault_match BOOLEAN DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            vault_id TEXT PRIMARY KEY,
            secret_type TEXT NOT NULL,
            argon2_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            times_detected INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS honeycomb_alerts (
            event_id TEXT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity TEXT,
            event_type TEXT NOT NULL,
            source TEXT,
            raw_extract TEXT,
            vault_ref TEXT,
            honeytoken_path TEXT NOT NULL,
            token_id TEXT NOT NULL,
            token_type TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            confidence REAL,
            process_name TEXT,
            process_id INTEGER,
            username TEXT,
            process_path TEXT,
            attribution_source TEXT
        )
    """)
    
    # Schema Migration for existing DBs
    try:
        cursor.execute("ALTER TABLE findings ADD COLUMN vault_match BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass
        
    try:
        cursor.execute("ALTER TABLE honeycomb_alerts ADD COLUMN username TEXT")
    except sqlite3.OperationalError:
        pass
        
    try:
        cursor.execute("ALTER TABLE honeycomb_alerts ADD COLUMN process_path TEXT")
    except sqlite3.OperationalError:
        pass
        
    try:
        cursor.execute("ALTER TABLE honeycomb_alerts ADD COLUMN attribution_source TEXT")
    except sqlite3.OperationalError:
        pass
        
    conn.commit()
    conn.close()

def save_finding(finding: Finding):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO findings (
            event_id, timestamp, severity, event_type, source, raw_extract, vault_ref,
            file_path, detector, entity_type, masked_value, context, confidence,
            line_number, validated, vault_match
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding.event_id, finding.timestamp, finding.severity, finding.event_type,
        finding.source, finding.raw_extract, finding.vault_ref, finding.file_path, finding.detector,
        finding.entity_type, finding.masked_value, finding.context, finding.confidence,
        finding.line_number, finding.validated, finding.vault_match
    ))
    conn.commit()
    conn.close()

def save_honeycomb_alert(alert: HoneycombAlert):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO honeycomb_alerts (
            event_id, timestamp, severity, event_type, source, raw_extract, vault_ref,
            honeytoken_path, token_id, token_type, incident_type, confidence, process_name, process_id,
            username, process_path, attribution_source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.event_id, alert.timestamp, alert.severity, alert.event_type,
        alert.source, alert.raw_extract, alert.vault_ref, alert.honeytoken_path,
        alert.token_id, alert.token_type, alert.incident_type, alert.confidence,
        alert.process_name, alert.process_id, alert.username, alert.process_path, alert.attribution_source
    ))
    conn.commit()
    conn.close()

def handle_finding_event(event: Finding):
    save_finding(event)

def handle_honeycomb_event(event: HoneycombAlert):
    save_honeycomb_alert(event)

# --- Vault Operations ---

def insert_vault_entry(vault_id: str, secret_type: str, argon2_hash: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vault (vault_id, secret_type, argon2_hash)
        VALUES (?, ?, ?)
    """, (vault_id, secret_type, argon2_hash))
    conn.commit()
    conn.close()

def delete_vault_entry(vault_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vault WHERE vault_id = ?", (vault_id,))
    conn.commit()
    conn.close()

def get_vault_entries_by_type(secret_type: str) -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT vault_id, argon2_hash, created_at, times_detected FROM vault WHERE secret_type = ?", (secret_type,))
    rows = cursor.fetchall()
    conn.close()
    return [{"vault_id": r[0], "argon2_hash": r[1], "created_at": r[2], "times_detected": r[3]} for r in rows]

def get_vault_entry_hash(vault_id: str) -> str:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT argon2_hash FROM vault WHERE vault_id = ?", (vault_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None

def get_all_vault_entries() -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT vault_id, secret_type, created_at, times_detected FROM vault ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"vault_id": r[0], "secret_type": r[1], "created_at": r[2], "times_detected": r[3]} for r in rows]

def increment_vault_detection(vault_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE vault SET times_detected = times_detected + 1 WHERE vault_id = ?", (vault_id,))
    conn.commit()
    conn.close()

def get_protected_findings() -> list:
    """Returns protected findings securely, strictly omitting raw_extract and context."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = """
        SELECT
            event_id, timestamp, severity, event_type, source,
            file_path, detector, entity_type, masked_value,
            confidence, line_number, validated, vault_match
        FROM findings
        WHERE vault_match = 1
        ORDER BY timestamp DESC
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {
            "event_id": r[0],
            "timestamp": r[1],
            "severity": r[2],
            "event_type": r[3],
            "source": r[4],
            "file_path": r[5],
            "detector": r[6],
            "entity_type": r[7],
            "masked_value": r[8],
            "confidence": r[9],
            "line_number": r[10],
            "validated": bool(r[11]),
            "vault_match": bool(r[12])
        }
        for r in rows
    ]

def get_regular_findings() -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings WHERE vault_match = 0 OR vault_match IS NULL ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows
