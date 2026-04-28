import os
import sqlite3
from datetime import date, timedelta

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(_BASE_DIR, 'ips_maliciosas.db')

CATEGORIES = ('high', 'mid', 'low')


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cols = [row[1] for row in conn.execute("PRAGMA table_info(ips)").fetchall()]

        if cols and 'category' not in cols:
            # Migración: datos existentes pasan a categoría 'high'
            conn.execute("ALTER TABLE ips RENAME TO ips_old")
            conn.execute("""
                CREATE TABLE ips (
                    ip                TEXT,
                    category          TEXT,
                    total_intentos    INTEGER DEFAULT 0,
                    abuse_score       INTEGER DEFAULT 0,
                    confidence_score  INTEGER DEFAULT 0,
                    first_seen        DATE,
                    last_seen         DATE,
                    PRIMARY KEY (ip, category)
                )
            """)
            conn.execute("""
                INSERT INTO ips
                    (ip, category, total_intentos, abuse_score, confidence_score, first_seen, last_seen)
                SELECT ip, 'high', total_intentos, abuse_score, confidence_score, first_seen, last_seen
                FROM ips_old
            """)
            conn.execute("DROP TABLE ips_old")
        elif not cols:
            conn.execute("""
                CREATE TABLE ips (
                    ip                TEXT,
                    category          TEXT,
                    total_intentos    INTEGER DEFAULT 0,
                    abuse_score       INTEGER DEFAULT 0,
                    confidence_score  INTEGER DEFAULT 0,
                    first_seen        DATE,
                    last_seen         DATE,
                    PRIMARY KEY (ip, category)
                )
            """)
        conn.commit()


def upsert_ip(ip, weekly_intentos, abuse_score, confidence_score, category, last_seen):
    with sqlite3.connect(DB_PATH) as conn:
        existing = conn.execute(
            "SELECT ip FROM ips WHERE ip = ? AND category = ?", (ip, category)
        ).fetchone()
        if existing:
            conn.execute("""
                UPDATE ips
                SET total_intentos   = total_intentos + ?,
                    abuse_score      = ?,
                    confidence_score = ?,
                    last_seen        = ?
                WHERE ip = ? AND category = ?
            """, (weekly_intentos, abuse_score, confidence_score, last_seen, ip, category))
        else:
            conn.execute("""
                INSERT INTO ips
                    (ip, category, total_intentos, abuse_score, confidence_score, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip, category, weekly_intentos, abuse_score, confidence_score, last_seen, last_seen))
        conn.commit()


def get_ip(ip):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM ips WHERE ip = ? ORDER BY category", (ip,)
        ).fetchall()
    return [dict(row) for row in rows]


def get_active_ips(max_days, category):
    cutoff = (date.today() - timedelta(days=max_days)).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT ip, total_intentos, abuse_score, confidence_score, first_seen, last_seen
            FROM ips
            WHERE last_seen >= ? AND category = ?
        """, (cutoff, category)).fetchall()
    return [dict(row) for row in rows]
