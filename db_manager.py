import os
import sqlite3
from datetime import date, timedelta

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_BASE_DIR, 'ips_maliciosas.db')


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ips (
                ip                TEXT PRIMARY KEY,
                total_intentos    INTEGER DEFAULT 0,
                abuse_score       INTEGER DEFAULT 0,
                confidence_score  INTEGER DEFAULT 0,
                first_seen        DATE,
                last_seen         DATE
            )
        """)
        conn.commit()


def upsert_ip(ip, weekly_intentos, abuse_score, confidence_score):
    today = date.today().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        existing = conn.execute(
            "SELECT ip FROM ips WHERE ip = ?", (ip,)
        ).fetchone()
        if existing:
            conn.execute("""
                UPDATE ips
                SET total_intentos   = total_intentos + ?,
                    abuse_score      = ?,
                    confidence_score = ?,
                    last_seen        = ?
                WHERE ip = ?
            """, (weekly_intentos, abuse_score, confidence_score, today, ip))
        else:
            conn.execute("""
                INSERT INTO ips
                    (ip, total_intentos, abuse_score, confidence_score, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ip, weekly_intentos, abuse_score, confidence_score, today, today))
        conn.commit()


def get_ip(ip):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM ips WHERE ip = ?", (ip,)).fetchone()
    return dict(row) if row else None


def get_active_ips(max_days):
    cutoff = (date.today() - timedelta(days=max_days)).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT ip, total_intentos, abuse_score, confidence_score, first_seen, last_seen
            FROM ips
            WHERE last_seen >= ?
        """, (cutoff,)).fetchall()
    return [dict(row) for row in rows]
