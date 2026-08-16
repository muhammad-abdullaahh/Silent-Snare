"""
data/logs.py - Persistent SQLite and in-memory event logger for SilentSnare.
"""

import sqlite3
import os
import time
from typing import List, Dict, Any


class EventLogger:
    """
    Manages persistent logging of captured packets, IDS detection alerts,
    and ARP simulation state transitions into SQLite database and memory buffers.
    """
    def __init__(self, db_path: str = "data/silentsnare.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Establish SQLite database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_time_str(self) -> str:
        """Return formatted current timestamp string."""
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def init_db(self) -> None:
        """Create log tables if they do not exist, and ensure compatible schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if packets table exists and if id column is incompatible integer type
            cursor.execute("PRAGMA table_info(packets)")
            table_info = cursor.fetchall()
            if table_info:
                id_col = next((row for row in table_info if row[1] == "id"), None)
                if id_col and "INT" in id_col[2].upper():
                    cursor.execute("DROP TABLE packets")

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    payload TEXT,
                    raw_payload TEXT,
                    is_encrypted INTEGER,
                    is_tampered INTEGER,
                    status TEXT,
                    intercepted_by TEXT
                )
            """)
            
            # Check for existing table missing columns
            cursor.execute("PRAGMA table_info(packets)")
            existing_cols = [row[1] for row in cursor.fetchall()]
            for col, col_type in [("raw_payload", "TEXT"), ("is_encrypted", "INTEGER"), ("is_tampered", "INTEGER"), ("status", "TEXT"), ("intercepted_by", "TEXT")]:
                if col not in existing_cols:
                    try:
                        cursor.execute(f"ALTER TABLE packets ADD COLUMN {col} {col_type}")
                    except Exception:
                        pass

            # Check for alerts table missing columns
            cursor.execute("PRAGMA table_info(alerts)")
            alerts_table = cursor.fetchall()
            if alerts_table:
                alerts_cols = [row[1] for row in alerts_table]
                if "type" not in alerts_cols:
                    cursor.execute("DROP TABLE alerts")
                    alerts_table = None

            if not alerts_table:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        severity TEXT,
                        type TEXT,
                        details TEXT,
                        recommendation TEXT
                    )
                """)

            # Check for events table missing columns
            cursor.execute("PRAGMA table_info(events)")
            events_table = cursor.fetchall()
            if events_table:
                events_cols = [row[1] for row in events_table]
                if "category" not in events_cols:
                    cursor.execute("DROP TABLE events")
                    events_table = None

            if not events_table:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        category TEXT,
                        message TEXT
                    )
                """)
            conn.commit()

    def log_packet(self, packet_dict: Dict[str, Any]) -> None:
        """Insert captured packet audit entry."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO packets 
                (id, timestamp, src_ip, dst_ip, protocol, payload, raw_payload, is_encrypted, is_tampered, status, intercepted_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                packet_dict.get("id"),
                packet_dict.get("timestamp"),
                packet_dict.get("src_ip"),
                packet_dict.get("dst_ip"),
                packet_dict.get("protocol"),
                packet_dict.get("payload"),
                packet_dict.get("raw_payload"),
                1 if packet_dict.get("is_encrypted") else 0,
                1 if packet_dict.get("is_tampered") else 0,
                packet_dict.get("status"),
                packet_dict.get("intercepted_by")
            ))
            conn.commit()

    def log_alert(self, alert_dict: Dict[str, Any]) -> None:
        """Record IDS security detection alert."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (timestamp, severity, type, details, recommendation)
                VALUES (?, ?, ?, ?, ?)
            """, (
                alert_dict.get("timestamp", self.get_time_str()),
                alert_dict.get("severity", "WARNING"),
                alert_dict.get("type", "General Alert"),
                alert_dict.get("details", ""),
                alert_dict.get("recommendation", "")
            ))
            conn.commit()

    def log_event(self, category: str, message: str) -> None:
        """Log system operational event or mitigation action."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO events (timestamp, category, message)
                VALUES (?, ?, ?)
            """, (self.get_time_str(), category, message))
            conn.commit()

    def get_packets(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent captured packet records."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM packets ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve IDS security alerts."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve operational system logs."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def clear_all_logs(self) -> None:
        """Wipe database logs for simulation reset."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM packets")
            cursor.execute("DELETE FROM alerts")
            cursor.execute("DELETE FROM events")
            conn.commit()
