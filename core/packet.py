import time
import uuid
import hashlib
from typing import List, Dict, Any, Optional


class Packet:

    def __init__(
        self,
        sender: str,
        receiver: str,
        protocol: str = "HTTP",
        payload: str = "",
        is_encrypted: bool = False,
        scenario_type: str = "computer_mitm",
        email_subject: Optional[str] = None
    ):
        self.id = f"PKT-{str(uuid.uuid4())[:6].upper()}"
        self.timestamp = time.strftime("%H:%M:%S")
        self.sender = sender
        self.receiver = receiver
        self.protocol = protocol.upper()
        self.payload = payload
        self.is_encrypted = is_encrypted
        self.scenario_type = scenario_type
        self.email_subject = email_subject

        self.is_tampered = False
        self.original_payload = payload
        self.status = "In-Transit"
        self.intercepted_by: Optional[str] = None
        self.hop_history: List[str] = []

    def record_hop(self, node_name: str) -> None:
        self.hop_history.append(node_name)

    def tamper_payload(self, new_payload: str, attacker_name: str) -> bool:
        if self.is_encrypted:
            return False

        if not self.is_tampered:
            self.original_payload = self.payload

        self.payload = new_payload
        self.is_tampered = True
        self.status = "Modified & Forwarded"
        self.intercepted_by = attacker_name
        return True

    def get_display_content(self) -> str:
        if self.is_encrypted:
            digest = hashlib.sha256(self.payload.encode("utf-8")).hexdigest().upper()
            return f"🔒 AES-256-GCM Ciphertext:\n0x7F4A{digest[:32]}\n0x{digest[32:]}E9F1"

        return self.payload

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "sender": self.sender,
            "receiver": self.receiver,
            "protocol": self.protocol,
            "display_payload": self.get_display_content(),
            "raw_payload": self.payload,
            "original_payload": self.original_payload,
            "is_encrypted": self.is_encrypted,
            "is_tampered": self.is_tampered,
            "status": self.status,
            "intercepted_by": self.intercepted_by or "None",
            "hops": " ➔ ".join(self.hop_history),
            "scenario_type": self.scenario_type,
            "email_subject": self.email_subject or "N/A"
        }
