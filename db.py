import json
import sqlite3
from collections import Counter


DEFAULT_DB_PATH = "logs/trapnest.db"


def _connect(db_path=DEFAULT_DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            service TEXT,
            ip TEXT,
            event TEXT,
            payload TEXT
        )
        """
    )
    return conn


def save_event(event, db_path=DEFAULT_DB_PATH):
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO events (ts, service, ip, event, payload) VALUES (?, ?, ?, ?, ?)",
            (
                event.get("ts"),
                event.get("service"),
                event.get("ip"),
                event.get("event"),
                json.dumps(event, ensure_ascii=False),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def summarize_events(db_path=DEFAULT_DB_PATH):
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT ts, service, ip, event, payload FROM events ORDER BY id"
        ).fetchall()
    finally:
        conn.close()

    total_events = len(rows)
    ips = Counter(row["ip"] for row in rows if row["ip"])
    services = Counter(row["service"] for row in rows if row["service"])
    return {
        "total_events": total_events,
        "top_ips": ips.most_common(5),
        "services": services.most_common(),
        "rows": [dict(row) for row in rows],
    }
