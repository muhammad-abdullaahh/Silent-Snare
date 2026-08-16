"""
core/devices.py - Network device representations for SilentSnare MITM Simulator.
"""

from typing import Dict, Optional, List


class NetworkDevice:
    """Base class for all network devices in the simulated LAN segment."""
    def __init__(self, hostname: str, ip: str, mac: str, role: str = "Host"):
        self.hostname = hostname
        self.ip = ip
        self.mac = mac
        self.role = role
        self.arp_table: Dict[str, str] = {}  # Maps IP -> MAC
        self.status = "Online"

    def update_arp_cache(self, ip: str, mac: str) -> None:
        """Update or insert an entry into the ARP cache table."""
        self.arp_table[ip] = mac

    def get_mac_for_ip(self, ip: str) -> Optional[str]:
        """Look up MAC address for a given IP in the local ARP table."""
        return self.arp_table.get(ip)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "mac": self.mac,
            "role": self.role,
            "status": self.status,
            "arp_table": self.arp_table.copy(),
        }


class Device(NetworkDevice):
    """Represents a standard victim machine / endpoint in the LAN."""
    def __init__(self, hostname: str, ip: str, mac: str):
        super().__init__(hostname, ip, mac, role="Victim / Client")


class Router(NetworkDevice):
    """Represents the Default Gateway in the local network segment."""
    def __init__(self, hostname: str = "Gateway Router", ip: str = "192.168.1.1", mac: str = "AA:BB:CC:DD:EE:01"):
        super().__init__(hostname, ip, mac, role="Default Gateway")


class Attacker(NetworkDevice):
    """
    Represents the SilentSnare Attacker node capable of ARP spoofing,
    intercepting traffic, modifying payloads, and triggering packet drops.
    """
    def __init__(self, hostname: str = "SilentSnare Attacker", ip: str = "192.168.1.99", mac: str = "DE:AD:BE:EF:66:66"):
        super().__init__(hostname, ip, mac, role="MITM Attacker")
        self.is_poisoning = False
        self.intercept_mode = "tamper"  # Options: "passive", "tamper", "drop"
        self.tamper_find_str = "USER_CREDENTIALS"
        self.tamper_replace_str = "INTERCEPTED_BY_SILENTSNARE"
        self.captured_packets_count = 0

    def set_tamper_rule(self, find_str: str, replace_str: str) -> None:
        """Configure active string replacement for plaintext packet tampering."""
        self.tamper_find_str = find_str
        self.tamper_replace_str = replace_str

    def poison_target_cache(self, target: NetworkDevice, spoofed_ip: str) -> None:
        """Inject malicious ARP response associating spoofed_ip with Attacker's MAC."""
        target.update_arp_cache(spoofed_ip, self.mac)
        self.is_poisoning = True

    def restore_target_cache(self, target: NetworkDevice, target_ip: str, authentic_mac: str) -> None:
        """Restore authentic IP-to-MAC mapping in target ARP cache."""
        target.update_arp_cache(target_ip, authentic_mac)
