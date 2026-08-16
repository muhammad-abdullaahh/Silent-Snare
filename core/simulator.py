"""
core/simulator.py - Pure in-memory MITM simulation engine for SilentSnare.
Exposes discrete step methods for Scenario 1 and Scenario 2.
"""

from typing import Dict, List, Tuple, Optional, Any
from core.devices import NetworkDevice, Device, Router, Attacker
from core.packet import Packet


class SimulatorEngine:
    """
    Simulation engine orchestrating in-memory devices, ARP cache states,
    step-by-step attack executions, and anomaly detection alerts.
    """
    def __init__(self, logger=None):
        self.logger = logger
        self.trigger_count = 0
        
        # Scenario 1 Devices (Computer to Computer)
        self.comp_a = Device(name="Computer A (Abdullah)", ip="192.168.1.10", mac="00:11:22:33:44:A1", role="Client")
        self.comp_b = Device(name="Computer B (Umer)", ip="192.168.1.20", mac="00:11:22:33:44:B2", role="Receiver")
        self.s1_attacker = Attacker(name="Attacker (Anonymous)", ip="192.168.1.99", mac="DE:AD:BE:EF:66:66")
        
        # Scenario 2 Devices (Email via Gateway)
        self.email_victim = Device(name="Victim (Abdullah)", ip="10.0.0.50", mac="11:22:33:44:55:66", role="Client")
        self.router = Router(name="Gateway Router", ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")
        self.mail_server = Device(name="Corporate Mail Server (Umer)", ip="10.0.0.254", mac="99:88:77:66:55:44", role="Mail Server")
        self.s2_attacker = Attacker(name="Attacker (Anonymous)", ip="10.0.0.99", mac="DE:AD:BE:EF:77:77")

        self.packets: List[Packet] = []
        self.alerts: List[Dict[str, Any]] = []

        self.setup_baseline_network()

    def setup_baseline_network(self) -> None:
        """Initialize clean, authentic ARP tables for both scenarios."""
        # Scenario 1 Baseline
        self.comp_a.update_arp_entry(self.comp_b.ip, self.comp_b.mac, is_baseline=True)
        self.comp_a.update_arp_entry(self.s1_attacker.ip, self.s1_attacker.mac, is_baseline=True)

        self.comp_b.update_arp_entry(self.comp_a.ip, self.comp_a.mac, is_baseline=True)
        self.comp_b.update_arp_entry(self.s1_attacker.ip, self.s1_attacker.mac, is_baseline=True)

        self.s1_attacker.update_arp_entry(self.comp_a.ip, self.comp_a.mac, is_baseline=True)
        self.s1_attacker.update_arp_entry(self.comp_b.ip, self.comp_b.mac, is_baseline=True)
        self.s1_attacker.is_poisoning = False

        # Scenario 2 Baseline
        self.email_victim.update_arp_entry(self.router.ip, self.router.mac, is_baseline=True)
        self.email_victim.update_arp_entry(self.mail_server.ip, self.mail_server.mac, is_baseline=True)

        self.router.update_arp_entry(self.email_victim.ip, self.email_victim.mac, is_baseline=True)
        self.router.update_arp_entry(self.mail_server.ip, self.mail_server.mac, is_baseline=True)

        self.mail_server.update_arp_entry(self.router.ip, self.router.mac, is_baseline=True)
        self.mail_server.update_arp_entry(self.email_victim.ip, self.email_victim.mac, is_baseline=True)

        self.s2_attacker.update_arp_entry(self.email_victim.ip, self.email_victim.mac, is_baseline=True)
        self.s2_attacker.update_arp_entry(self.router.ip, self.router.mac, is_baseline=True)
        self.s2_attacker.is_poisoning = False

        if self.logger:
            self.logger.log_event("SYSTEM", "Clean baseline ARP caches initialized.")

    def get_trigger_id(self) -> int:
        """Increment trigger sequence for UI animation re-rendering."""
        self.trigger_count += 1
        return self.trigger_count

    # ------------------------------------------------------------------
    # SCENARIO 1: MITM Between Two Computers
    # ------------------------------------------------------------------
    def s1_normal_communication(self, payload: str = "Hello Umer! Secret code: 9876", protocol: str = "HTTP") -> Packet:
        """Step 1: Computer A sends message directly to Computer B (baseline clean)."""
        packet = Packet(
            sender=self.comp_a.name,
            receiver=self.comp_b.name,
            protocol=protocol,
            payload=payload,
            is_encrypted=False,
            scenario_type="computer_mitm"
        )
        packet.record_hop(self.comp_a.name)
        packet.record_hop(self.comp_b.name)
        packet.status = "Delivered (Direct Clean Path)"

        self.packets.append(packet)
        if self.logger:
            self.logger.log_packet(packet.to_dict())
            self.logger.log_event("SCENARIO_1", f"Normal packet {packet.id} sent directly A -> B.")
        return packet

    def s1_arp_spoof(self) -> List[Dict[str, Any]]:
        """Step 2: Attacker poisons Computer A & B ARP tables."""
        # Poison Computer A: thinks Computer B is at Attacker MAC
        self.s1_attacker.poison_target_arp(self.comp_a, self.comp_b.ip)
        # Poison Computer B: thinks Computer A is at Attacker MAC
        self.s1_attacker.poison_target_arp(self.comp_b, self.comp_a.ip)

        msg = f"ARP Poisoned: Computer A & B traffic redirected to Attacker MAC ({self.s1_attacker.mac})."
        if self.logger:
            self.logger.log_event("SCENARIO_1_ATTACK", msg)

        return self.detect_arp_anomalies()

    def s1_intercepted_communication(
        self,
        payload: str = "Hello Umer! Secret code: 9876",
        protocol: str = "HTTP",
        is_encrypted: bool = False,
        modified_payload: str = "Hello Umer! TRANSFER $10,000 to Anonymous Account #666"
    ) -> Packet:
        """Step 3/4: Computer A sends message to B; routed through Attacker."""
        packet = Packet(
            sender=self.comp_a.name,
            receiver=self.comp_b.name,
            protocol=protocol,
            payload=payload,
            is_encrypted=is_encrypted,
            scenario_type="computer_mitm"
        )

        packet.record_hop(self.comp_a.name)
        packet.record_hop(self.s1_attacker.name)
        self.s1_attacker.captured_count += 1
        packet.intercepted_by = self.s1_attacker.name

        if is_encrypted:
            # Encrypted packet intercepted but cannot be modified
            packet.record_hop(self.comp_b.name)
            packet.status = "Intercepted (Encrypted - TLS Protected)"
            if self.logger:
                self.logger.log_event("SCENARIO_1_SECURITY", f"Packet {packet.id} intercepted but unreadable due to SSL/TLS.")
        else:
            # Unencrypted packet read & modified
            packet.tamper_payload(modified_payload, self.s1_attacker.name)
            packet.record_hop(self.comp_b.name)
            if self.logger:
                self.logger.log_event("SCENARIO_1_ATTACK", f"Packet {packet.id} intercepted and payload altered by Attacker!")

        self.packets.append(packet)
        if self.logger:
            self.logger.log_packet(packet.to_dict())
        return packet

    def s1_restore_arp(self) -> None:
        """Step 5: Restore authentic ARP tables for Scenario 1."""
        self.s1_attacker.restore_target_arp(self.comp_a, self.comp_b.ip, self.comp_b.mac)
        self.s1_attacker.restore_target_arp(self.comp_b, self.comp_a.ip, self.comp_a.mac)
        self.s1_attacker.is_poisoning = False
        if self.logger:
            self.logger.log_event("SCENARIO_1_MITIGATION", "Authentic ARP cache restored for Scenario 1.")

    # ------------------------------------------------------------------
    # SCENARIO 2: Email Hijacking via Network Gateway Spoofing
    # ------------------------------------------------------------------
    def s2_normal_email(
        self,
        subject: str = "Q3 Financial Payroll Report",
        body: str = "Please process bonus payments for dev team.",
        sender: str = "abdullah@company.com",
        recipient: str = "umer@company.com",
        protocol: str = "SMTP"
    ) -> Packet:
        """Step 1: Victim sends email through Gateway Router to Mail Server (normal)."""
        payload = f"Subject: {subject} | From: {sender} | To: {recipient} | Body: {body}"
        packet = Packet(
            sender=self.email_victim.name,
            receiver=self.mail_server.name,
            protocol=protocol,
            payload=payload,
            is_encrypted=False,
            scenario_type="email_gateway",
            email_subject=subject
        )
        packet.record_hop(self.email_victim.name)
        packet.record_hop(self.router.name)
        packet.record_hop(self.mail_server.name)
        packet.status = "Delivered (Direct Gateway Route)"

        self.packets.append(packet)
        if self.logger:
            self.logger.log_packet(packet.to_dict())
            self.logger.log_event("SCENARIO_2", f"Normal email {packet.id} routed through Gateway Router.")
        return packet

    def s2_gateway_spoof(self) -> List[Dict[str, Any]]:
        """Step 2: Attacker poisons Victim's ARP table (impersonating Gateway Router)."""
        # Poison Victim Computer: thinks Gateway Router (10.0.0.1) is at Attacker MAC
        self.s2_attacker.poison_target_arp(self.email_victim, self.router.ip)

        msg = f"Gateway Spoof Active: Victim ({self.email_victim.ip}) Gateway ARP redirected to Attacker ({self.s2_attacker.mac})."
        if self.logger:
            self.logger.log_event("SCENARIO_2_ATTACK", msg)

        return self.detect_arp_anomalies()

    def s2_intercepted_email(
        self,
        subject: str = "Q3 Financial Payroll Report",
        body: str = "Please process bonus payments for dev team.",
        sender: str = "abdullah@company.com",
        recipient: str = "umer@company.com",
        protocol: str = "SMTP",
        is_encrypted: bool = False,
        modified_body: str = "HIJACKED BY ANONYMOUS: Wire all funds to offshore account #998877!"
    ) -> Packet:
        """Step 3/4: Victim sends email; routed through Attacker impersonating Gateway Router."""
        payload = f"Subject: {subject} | From: {sender} | To: {recipient} | Body: {body}"
        packet = Packet(
            sender=self.email_victim.name,
            receiver=self.mail_server.name,
            protocol=protocol,
            payload=payload,
            is_encrypted=is_encrypted,
            scenario_type="email_gateway",
            email_subject=subject
        )

        packet.record_hop(self.email_victim.name)
        packet.record_hop(self.s2_attacker.name)
        self.s2_attacker.captured_count += 1
        packet.intercepted_by = self.s2_attacker.name

        if is_encrypted:
            # Encrypted SMTPS/IMAPS packet
            packet.record_hop(self.router.name)
            packet.record_hop(self.mail_server.name)
            packet.status = "Intercepted (Encrypted SMTPS - TLS Protected)"
            if self.logger:
                self.logger.log_event("SCENARIO_2_SECURITY", f"Email {packet.id} intercepted at gateway but unreadable due to SMTPS/TLS.")
        else:
            # Unencrypted email hijacked & modified
            modified_payload = f"Subject: [HIJACKED] {subject} | From: {sender} | To: {recipient} | Body: {modified_body}"
            packet.tamper_payload(modified_payload, self.s2_attacker.name)
            packet.record_hop(self.router.name)
            packet.record_hop(self.mail_server.name)
            packet.status = "Email Hijacked & Forwarded"
            if self.logger:
                self.logger.log_event("SCENARIO_2_ATTACK", f"Email {packet.id} intercepted at gateway and body modified by Attacker!")

        self.packets.append(packet)
        if self.logger:
            self.logger.log_packet(packet.to_dict())
        return packet

    def s2_restore_arp(self) -> None:
        """Step 5: Restore clean Gateway ARP cache for Scenario 2."""
        self.s2_attacker.restore_target_arp(self.email_victim, self.router.ip, self.router.mac)
        self.s2_attacker.is_poisoning = False
        if self.logger:
            self.logger.log_event("SCENARIO_2_MITIGATION", "Authentic Gateway ARP cache restored for Scenario 2.")

    # ------------------------------------------------------------------
    # ANOMALY DETECTION & HELPER METHODS
    # ------------------------------------------------------------------
    def detect_arp_anomalies(self) -> List[Dict[str, Any]]:
        """
        IDS Anomaly Detection: Scans all device ARP tables for IP-to-MAC duplication.
        Generates alert events when an untrusted MAC claims multiple IP addresses.
        """
        new_alerts = []

        # Check Scenario 1
        if self.comp_a.get_mac_for_ip(self.comp_b.ip) == self.s1_attacker.mac:
            alert = {
                "timestamp": self.logger.get_time_str() if self.logger else "14:00:00",
                "severity": "CRITICAL",
                "type": "ARP Cache Poisoning Detected (Scenario 1)",
                "details": f"Host {self.comp_a.name} ARP entry for IP {self.comp_b.ip} points to Attacker MAC ({self.s1_attacker.mac})!",
                "recommendation": "Implement Static ARP entries or Dynamic ARP Inspection (DAI) / 802.1X port security."
            }
            new_alerts.append(alert)
            self.alerts.append(alert)
            if self.logger:
                self.logger.log_alert(alert)

        # Check Scenario 2
        if self.email_victim.get_mac_for_ip(self.router.ip) == self.s2_attacker.mac:
            alert = {
                "timestamp": self.logger.get_time_str() if self.logger else "14:00:00",
                "severity": "CRITICAL",
                "type": "Gateway ARP Impersonation Detected (Scenario 2)",
                "details": f"Victim ARP cache for Gateway Router ({self.router.ip}) points to Attacker MAC ({self.s2_attacker.mac})!",
                "recommendation": "Deploy DHCP Snooping with DAI to validate ARP replies against binding database."
            }
            new_alerts.append(alert)
            self.alerts.append(alert)
            if self.logger:
                self.logger.log_alert(alert)

        return new_alerts

    def reset_all(self) -> None:
        """Reset all devices, packets, alerts, and counters."""
        self.packets.clear()
        self.alerts.clear()
        self.trigger_count = 0
        self.s1_attacker.captured_count = 0
        self.s2_attacker.captured_count = 0
        self.setup_baseline_network()
        if self.logger:
            self.logger.clear_all_logs()
