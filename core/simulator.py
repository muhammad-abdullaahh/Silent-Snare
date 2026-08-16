"""
core/simulator.py - Main simulation engine for SilentSnare MITM attack execution & monitoring.
"""

from typing import Dict, List, Tuple, Optional, Any
from core.devices import NetworkDevice, Device, Router, Attacker
from core.packet import Packet


class SimulatorEngine:
    """
    Core engine managing simulated network topology, ARP cache states,
    MITM packet routing, anomaly detection, and alert generation.
    """
    def __init__(self, logger=None):
        self.logger = logger
        self.devices: Dict[str, NetworkDevice] = {}
        self.packets: List[Packet] = []
        self.alerts: List[Dict[str, Any]] = []
        
        # Initialize default topology
        self.setup_default_network()

    def setup_default_network(self) -> None:
        """Instantiate standard LAN topology: Gateway Router, Victim Client, Victim Server, Attacker."""
        router = Router(hostname="Gateway Router", ip="192.168.1.1", mac="AA:BB:CC:DD:EE:01")
        victim_client = Device(hostname="Victim Client (Alice)", ip="192.168.1.10", mac="00:11:22:33:44:55")
        victim_server = Device(hostname="Email Gateway (Bob)", ip="192.168.1.20", mac="00:11:22:33:44:66")
        attacker = Attacker(hostname="SilentSnare Attacker", ip="192.168.1.99", mac="DE:AD:BE:EF:66:66")

        self.devices = {
            "router": router,
            "victim_client": victim_client,
            "victim_server": victim_server,
            "attacker": attacker
        }
        
        self.restore_clean_arp_tables()

    def restore_clean_arp_tables(self) -> None:
        """Populate authentic, unpoisoned ARP caches across all devices."""
        router = self.devices["router"]
        victim_client = self.devices["victim_client"]
        victim_server = self.devices["victim_server"]
        attacker = self.devices["attacker"]

        # Clean ARP entries
        router.update_arp_cache(victim_client.ip, victim_client.mac)
        router.update_arp_cache(victim_server.ip, victim_server.mac)
        router.update_arp_cache(attacker.ip, attacker.mac)

        victim_client.update_arp_cache(router.ip, router.mac)
        victim_client.update_arp_cache(victim_server.ip, victim_server.mac)
        victim_client.update_arp_cache(attacker.ip, attacker.mac)

        victim_server.update_arp_cache(router.ip, router.mac)
        victim_server.update_arp_cache(victim_client.ip, victim_client.mac)
        victim_server.update_arp_cache(attacker.ip, attacker.mac)

        attacker.update_arp_cache(router.ip, router.mac)
        attacker.update_arp_cache(victim_client.ip, victim_client.mac)
        attacker.update_arp_cache(victim_server.ip, victim_server.mac)
        
        attacker.is_poisoning = False
        if self.logger:
            self.logger.log_event("SYSTEM", "Clean ARP tables restored across LAN.")

    def start_arp_spoof(self) -> List[Dict[str, Any]]:
        """
        Execute ARP Cache Poisoning Attack.
        Attacker advertises its MAC for Gateway IP to Victim, and for Victim IP to Gateway.
        """
        attacker: Attacker = self.devices["attacker"]
        victim_client = self.devices["victim_client"]
        router = self.devices["router"]

        # Poison Victim Client: thinks Gateway and Victim Server are at Attacker MAC
        attacker.poison_target_cache(victim_client, router.ip)
        attacker.poison_target_cache(victim_client, self.devices["victim_server"].ip)
        # Poison Gateway & Server: think Victim Client is at Attacker MAC
        attacker.poison_target_cache(router, victim_client.ip)
        attacker.poison_target_cache(self.devices["victim_server"], victim_client.ip)

        msg = f"ARP Poisoning Active: {victim_client.hostname} & {router.hostname} traffic redirected through Attacker ({attacker.mac})."
        
        if self.logger:
            self.logger.log_event("ATTACK", msg)

        # Run anomaly detection
        new_alerts = self.detect_anomalies()
        return new_alerts

    def stop_arp_spoof(self) -> None:
        """Stop attack and restore authentic ARP cache bindings."""
        self.restore_clean_arp_tables()
        if self.logger:
            self.logger.log_event("MITIGATION", "ARP Spoofing terminated. Authentic ARP bindings restored.")

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        IDS/Detection module: Analyzes ARP tables for spoofing signatures.
        Detects IP-MAC duplication (same MAC assigned to multiple IPs).
        """
        detected_alerts = []
        attacker = self.devices["attacker"]
        router = self.devices["router"]
        victim_client = self.devices["victim_client"]

        # Check if router's IP resolve to attacker MAC in victim ARP cache
        if victim_client.get_mac_for_ip(router.ip) == attacker.mac:
            alert = {
                "timestamp": self.logger.get_time_str() if self.logger else "12:00:00",
                "severity": "CRITICAL",
                "type": "ARP Cache Poisoning Detected",
                "details": f"Gateway IP {router.ip} is mapped to untrusted MAC {attacker.mac} on host {victim_client.hostname}!",
                "recommendation": "Deploy Static ARP tables or dynamic ARP inspection (DAI) / DHCP snooping."
            }
            detected_alerts.append(alert)
            self.alerts.append(alert)
            if self.logger:
                self.logger.log_alert(alert)

        return detected_alerts

    def send_packet(
        self,
        src_key: str = "victim_client",
        dst_key: str = "victim_server",
        protocol: str = "HTTP",
        payload: str = "USER_CREDENTIALS: admin / SecretPassword123",
        is_encrypted: bool = False
    ) -> Packet:
        """
        Simulate sending a data packet between network devices.
        Routes packet according to target host's ARP table.
        """
        src_dev = self.devices[src_key]
        dst_dev = self.devices[dst_key]
        router = self.devices["router"]
        attacker: Attacker = self.devices["attacker"]

        # Next hop resolution based on ARP table
        resolved_mac_for_target = src_dev.get_mac_for_ip(dst_dev.ip) or src_dev.get_mac_for_ip(router.ip)

        packet = Packet(
            src_ip=src_dev.ip,
            dst_ip=dst_dev.ip,
            src_mac=src_dev.mac,
            dst_mac=resolved_mac_for_target,
            protocol=protocol,
            payload=payload,
            is_encrypted=is_encrypted
        )

        packet.record_hop(src_dev.hostname)

        # Check if traffic passes through Attacker MAC
        if resolved_mac_for_target == attacker.mac and attacker.is_poisoning:
            packet.record_hop(attacker.hostname)
            attacker.captured_packets_count += 1
            packet.intercepted_by = attacker.hostname

            if attacker.intercept_mode == "drop":
                packet.status = "Dropped (DoS)"
                if self.logger:
                    self.logger.log_event("ATTACK_ACTION", f"Packet {packet.id} dropped by Attacker (Denial of Service).")
            elif attacker.intercept_mode == "tamper":
                if not is_encrypted:
                    # Tamper unencrypted payload
                    modified_payload = payload.replace("USER_CREDENTIALS", "SPOOFED_CREDENTIALS")
                    if modified_payload == payload:
                        modified_payload = f"[MODIFIED BY MITM] {payload}"
                    packet.tamper_payload(modified_payload, attacker.hostname)
                    packet.record_hop(dst_dev.hostname)
                    packet.status = "Modified & Forwarded"
                else:
                    # Payload is encrypted with SSL/TLS
                    packet.status = "Intercepted (Encrypted)"
                    packet.record_hop(dst_dev.hostname)
            else:  # Passive sniffing
                packet.status = "Intercepted (Sniffed)"
                packet.record_hop(dst_dev.hostname)
        else:
            # Direct authentic transmission
            packet.record_hop(dst_dev.hostname)
            packet.status = "Delivered (Direct)"

        self.packets.append(packet)
        if self.logger:
            self.logger.log_packet(packet.to_dict())

        return packet

    def get_topology_data() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Returns nodes and edges structured for graph UI visualization."""
        nodes = []
        for key, dev in self.devices.items():
            nodes.append({
                "id": dev.hostname,
                "label": f"{dev.hostname}\n({dev.ip})",
                "role": dev.role,
                "mac": dev.mac,
                "is_attacker": key == "attacker"
            })

        attacker = self.devices["attacker"]
        edges = []
        if attacker.is_poisoning:
            edges = [
                {"from": "Victim Client (Alice)", "to": "SilentSnare Attacker", "label": "Intercepted", "color": "#FF4B4B"},
                {"from": "SilentSnare Attacker", "to": "Gateway Router", "label": "Forwarded", "color": "#FF4B4B"},
                {"from": "Gateway Router", "to": "Email Gateway (Bob)", "label": "Transit", "color": "#00CC96"}
            ]
        else:
            edges = [
                {"from": "Victim Client (Alice)", "to": "Gateway Router", "label": "Direct", "color": "#00CC96"},
                {"from": "Gateway Router", "to": "Email Gateway (Bob)", "label": "Direct", "color": "#00CC96"},
                {"from": "SilentSnare Attacker", "to": "Gateway Router", "label": "Idle", "color": "#666666"}
            ]
        return nodes, edges
