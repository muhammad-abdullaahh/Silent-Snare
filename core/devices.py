"""
core/devices.py - Network Device & Attacker modeling for SilentSnare MITM Simulator.
"""

from typing import Dict, Optional, List, Any


class NetworkDevice:
    """
    Base class representing a simulated network device (Computer, Router, Server).
    Maintains local in-memory ARP table and baseline clean ARP state for comparison.
    """
    def __init__(self, name: str, ip: str, mac: str, role: str = "Host"):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.role = role
        self.arp_table: Dict[str, str] = {}        # Current active ARP table: IP -> MAC
        self.clean_arp_table: Dict[str, str] = {}  # Baseline unpoisoned ARP cache backup

    def update_arp_entry(self, ip: str, mac: str, is_baseline: bool = False) -> None:
        """Insert or update an entry in the local ARP table."""
        self.arp_table[ip] = mac
        if is_baseline or ip not in self.clean_arp_table:
            self.clean_arp_table[ip] = mac

    def get_mac_for_ip(self, ip: str) -> Optional[str]:
        """Look up MAC address for a given target IP."""
        return self.arp_table.get(ip)

    def get_arp_comparison(self) -> List[Dict[str, Any]]:
        """
        Return structured before & after ARP cache comparison records
        for UI display, highlighting poisoned entries.
        """
        records = []
        for target_ip, current_mac in self.arp_table.items():
            original_mac = self.clean_arp_table.get(target_ip, current_mac)
            is_poisoned = (current_mac != original_mac)
            records.append({
                "Device": self.name,
                "Target IP": target_ip,
                "Current MAC (After)": current_mac,
                "Original MAC (Before)": original_mac,
                "Is Poisoned": is_poisoned,
                "Status": "⚠️ POISONED" if is_poisoned else "AUTHENTIC"
            })
        return records

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "ip": self.ip,
            "mac": self.mac,
            "role": self.role,
            "arp_table": self.arp_table.copy(),
            "clean_arp_table": self.clean_arp_table.copy()
        }


class Device(NetworkDevice):
    """Represents a regular victim endpoint / computer or server."""
    def __init__(self, name: str, ip: str, mac: str, role: str = "Client"):
        super().__init__(name, ip, mac, role=role)


class Router(NetworkDevice):
    """Represents the Default Gateway Router in the local subnet."""
    def __init__(self, name: str = "Gateway Router", ip: str = "192.168.1.1", mac: str = "AA:BB:CC:DD:EE:01"):
        super().__init__(name, ip, mac, role="Default Gateway")


class Attacker(NetworkDevice):
    """
    Represents the SilentSnare Attacker node capable of poisoning target ARP caches,
    intercepting traffic, modifying payloads, and dropping packets.
    """
    def __init__(self, name: str = "Attacker (SilentSnare)", ip: str = "192.168.1.99", mac: str = "DE:AD:BE:EF:66:66"):
        super().__init__(name, ip, mac, role="MITM Attacker")
        self.is_poisoning = False
        self.intercept_mode = "tamper"  # "tamper", "passive", "drop"
        self.captured_count = 0

    def poison_target_arp(self, target_dev: NetworkDevice, target_ip: str) -> None:
        """
        Inject fake ARP response into target_dev's ARP cache.
        Tells target_dev that target_ip resolves to Attacker's MAC.
        """
        target_dev.update_arp_entry(target_ip, self.mac, is_baseline=False)
        self.is_poisoning = True

    def restore_target_arp(self, target_dev: NetworkDevice, target_ip: str, authentic_mac: str) -> None:
        """Restore clean authentic MAC binding in target_dev's ARP cache."""
        target_dev.update_arp_entry(target_ip, authentic_mac, is_baseline=False)
