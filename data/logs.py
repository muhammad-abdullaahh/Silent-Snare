"""
data/logs.py - Pure in-memory and SQLite logger for SilentSnare MITM Simulator.
"""

import sqlite3
import os
import time
from typing import List, Dict, Any


class EventLogger:
    """
    Manages in-memory log queues and optional SQLite database persistence
    for captured packets, security alerts, and system events.
    """
    def __init__(self, db_path: str = "data/silentsnare.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Fast in-memory storage buffers
        self.memory_packets: List[Dict[str, Any]] = []
        self.memory_alerts: List[Dict[str, Any]] = []
        self.memory_events: List[Dict[str, Any]] = []

        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Establish SQLite database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_time_str(self) -> str:
        """Return current timestamp string."""
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def init_db(self) -> None:
        """Initialize clean SQLite schema."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    sender TEXT,
                    receiver TEXT,
                    protocol TEXT,
                    display_payload TEXT,
                    raw_payload TEXT,
                    original_payload TEXT,
                    is_encrypted INTEGER,
                    is_tampered INTEGER,
                    status TEXT,
                    intercepted_by TEXT,
                    hops TEXT,
                    scenario_type TEXT,
                    email_subject TEXT
                )
            """)
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
        """Log packet to in-memory list and SQLite database."""
        self.memory_packets.insert(0, packet_dict)  # prepend latest first
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO packets 
                    (id, timestamp, sender, receiver, protocol, display_payload, raw_payload, original_payload, 
                     is_encrypted, is_tampered, status, intercepted_by, hops, scenario_type, email_subject)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    packet_dict.get("id"),
                    packet_dict.get("timestamp"),
                    packet_dict.get("sender"),
                    packet_dict.get("receiver"),
                    packet_dict.get("protocol"),
                    packet_dict.get("display_payload"),
                    packet_dict.get("raw_payload"),
                    packet_dict.get("original_payload"),
                    1 if packet_dict.get("is_encrypted") else 0,
                    1 if packet_dict.get("is_tampered") else 0,
                    packet_dict.get("status"),
                    packet_dict.get("intercepted_by"),
                    packet_dict.get("hops"),
                    packet_dict.get("scenario_type"),
                    packet_dict.get("email_subject")
                ))
                conn.commit()
        except Exception:
            pass

    def log_alert(self, alert_dict: Dict[str, Any]) -> None:
        """Log security detection alert."""
        self.memory_alerts.insert(0, alert_dict)
        try:
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
        except Exception:
            pass

    def log_event(self, category: str, message: str) -> None:
        """Log operational system event."""
        event_entry = {"timestamp": self.get_time_str(), "category": category, "message": message}
        self.memory_events.insert(0, event_entry)
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO events (timestamp, category, message)
                    VALUES (?, ?, ?)
                """, (event_entry["timestamp"], category, message))
                conn.commit()
        except Exception:
            pass

    def get_packets(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent captured packet records."""
        return self.memory_packets[:limit]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return IDS security alerts."""
        return self.memory_alerts[:limit]

    def get_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return system operational logs."""
        return self.memory_events[:limit]

    def clear_all_logs(self) -> None:
        """Wipe memory queues and database tables."""
        self.memory_packets.clear()
        self.memory_alerts.clear()
        self.memory_events.clear()
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM packets")
                cursor.execute("DELETE FROM alerts")
                cursor.execute("DELETE FROM events")
                conn.commit()
        except Exception:
            pass
