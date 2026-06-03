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
            validated BOOLEAN
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
            line_number, validated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding.event_id, finding.timestamp, finding.severity, finding.event_type,
        finding.source, finding.raw_extract, finding.vault_ref, finding.file_path, finding.detector,
        finding.entity_type, finding.masked_value, finding.context, finding.confidence,
        finding.line_number, finding.validated
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
