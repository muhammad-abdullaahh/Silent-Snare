from typing import Dict, Optional, List, Any


class NetworkDevice:

    def __init__(self, name: str, ip: str, mac: str, role: str = "Host"):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.role = role

        self.arp_table: Dict[str, str] = {}
        self.clean_arp_table: Dict[str, str] = {}

    def update_arp_entry(self, ip: str, mac: str, is_baseline: bool = False) -> None:
        self.arp_table[ip] = mac
        if is_baseline or ip not in self.clean_arp_table:
            self.clean_arp_table[ip] = mac

    def get_mac_for_ip(self, ip: str) -> Optional[str]:
        return self.arp_table.get(ip)

    def get_arp_comparison(self) -> List[Dict[str, Any]]:
        records = []
        for target_ip, current_mac in self.arp_table.items():
            original_mac = self.clean_arp_table.get(target_ip, current_mac)
            is_poisoned = (current_mac != original_mac)

            records.append({
                "Device": self.name,
                "Device IP": self.ip,
                "Target IP": target_ip,
                "MAC Address": current_mac,
                "Original MAC (Baseline)": original_mac,
                "Status": "⚠️ POISONED (Spoofed)" if is_poisoned else "AUTHENTIC"
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

    def __init__(self, name: str, ip: str, mac: str, role: str = "Client"):
        super().__init__(name, ip, mac, role=role)


class Router(NetworkDevice):

    def __init__(self, name: str = "Gateway Router", ip: str = "192.168.1.1", mac: str = "AA:BB:CC:DD:EE:01"):
        super().__init__(name, ip, mac, role="Default Gateway")


class Attacker(NetworkDevice):

    def __init__(self, name: str = "Attacker (Anonymous)", ip: str = "192.168.1.99", mac: str = "DE:AD:BE:EF:66:66"):
        super().__init__(name, ip, mac, role="MITM Attacker")
        self.is_poisoning = False
        self.intercept_mode = "tamper"
        self.captured_count = 0

    def poison_target_arp(self, target_dev: NetworkDevice, target_ip: str) -> None:
        target_dev.update_arp_entry(target_ip, self.mac, is_baseline=False)
        self.is_poisoning = True

    def restore_target_arp(self, target_dev: NetworkDevice, target_ip: str, authentic_mac: str) -> None:
        target_dev.update_arp_entry(target_ip, authentic_mac, is_baseline=False)
