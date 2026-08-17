import sqlite3
import os
import time
import logging
from typing import List, Dict, Any


class EventLogger:
    """
    Handles in-memory log management and SQLite database persistence
    for captured packets, security alerts, and system logs.
    """

    def __init__(self, db_path: str = "data/silentsnare.db"):
        self.db_path = db_path
        
        # Ensure target database directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self.memory_packets: List[Dict[str, Any]] = []
        self.memory_alerts: List[Dict[str, Any]] = []
        self.memory_events: List[Dict[str, Any]] = []

        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Returns a new SQLite database connection with row factory configured."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_time_str(self) -> str:
        """Returns formatted timestamp string."""
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def init_db(self) -> None:
        """Creates SQLite tables for packets, security alerts, and events if missing."""
        try:
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
        except sqlite3.Error as err:
            logging.error(f"Database initialization failed: {err}")

    def log_packet(self, packet_dict: Dict[str, Any]) -> None:
        """Logs packet information into memory and SQLite database."""
        self.memory_packets.insert(0, packet_dict)

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
        except sqlite3.Error as err:
            logging.error(f"Failed to log packet to database: {err}")

    def log_alert(self, alert_dict: Dict[str, Any]) -> None:
        """Logs security detection alert to memory and database."""
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
        except sqlite3.Error as err:
            logging.error(f"Failed to log alert to database: {err}")

    def log_event(self, category: str, message: str) -> None:
        """Logs system operations into memory and database."""
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
        except sqlite3.Error as err:
            logging.error(f"Failed to log event to database: {err}")

    def get_packets(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent packet entries."""
        return self.memory_packets[:limit]

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent security alert entries."""
        return self.memory_alerts[:limit]

    def get_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent system log entries."""
        return self.memory_events[:limit]

    def clear_all_logs(self) -> None:
        """Clears memory buffers and deletes database records."""
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
        except sqlite3.Error as err:
            logging.error(f"Failed to clear database logs: {err}")
