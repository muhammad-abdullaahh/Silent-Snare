"""
core/packet.py - Data packet frame representation for SilentSnare MITM Simulator.
"""

import time
import uuid
from typing import List, Dict, Any, Optional


class Packet:
    """
    Represents a network packet frame transmitted between hosts.
    Tracks protocol attributes, encryption state, payload content,
    and routing hop history across simulated ARP topologies.
    """
    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_mac: str,
        dst_mac: str,
        protocol: str = "HTTP",
        payload: str = "",
        is_encrypted: bool = False
    ):
        self.id = str(uuid.uuid4())[:8]
        self.timestamp = time.strftime("%H:%M:%S")
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.protocol = protocol.upper()
        self.payload = payload
        self.is_encrypted = is_encrypted
        
        # Security & Interception audit fields
        self.is_tampered = False
        self.original_payload = payload
        self.status = "In-Transit"  # "Delivered", "Intercepted", "Modified", "Dropped"
        self.intercepted_by: Optional[str] = None
        self.hop_history: List[str] = []

    def record_hop(self, node_name: str) -> None:
        """Append node to routing hop trail."""
        self.hop_history.append(node_name)

    def tamper_payload(self, new_payload: str, attacker_name: str) -> None:
        """Modify packet payload if traffic is unencrypted."""
        if not self.is_encrypted:
            if not self.is_tampered:
                self.original_payload = self.payload
            self.payload = new_payload
            self.is_tampered = True
            self.status = "Modified"
            self.intercepted_by = attacker_name

    def get_display_payload(self) -> str:
        """Return formatted payload for display, accounting for encryption."""
        if self.is_encrypted:
            return "🔒 [ENCRYPTED TLS/SSL PAYLOAD - UNREADABLE TO ATTACKER]"
        return self.payload

    def to_dict(self) -> Dict[str, Any]:
        """Convert packet state to dictionary for logging and dataframe visualization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "protocol": self.protocol,
            "payload": self.get_display_payload(),
            "raw_payload": self.payload,
            "original_payload": self.original_payload,
            "is_encrypted": self.is_encrypted,
            "is_tampered": self.is_tampered,
            "status": self.status,
            "intercepted_by": self.intercepted_by or "None",
            "hops": " -> ".join(self.hop_history)
        }
