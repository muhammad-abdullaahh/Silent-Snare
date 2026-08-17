from typing import Dict, List, Optional, Any
from core.devices import NetworkDevice, Device, Router, Attacker
from core.packet import Packet


class SimulatorEngine:
    """
    Simulation engine managing device topology, ARP cache poisoning,
    packet routing, and intrusion detection alerts.
    """

    def __init__(self, logger=None):
        self.logger = logger
        self.trigger_count = 0

        # Scenario 1 Nodes: Direct Computer-to-Computer Communication
        self.comp_a = Device(name="Computer A (Abdullah)", ip="192.168.1.10", mac="00:11:22:33:44:A1", role="Client")
        self.comp_b = Device(name="Computer B (Umer)", ip="192.168.1.20", mac="00:11:22:33:44:B2", role="Receiver")
        self.s1_attacker = Attacker(name="Attacker (Anonymous)", ip="192.168.1.99", mac="DE:AD:BE:EF:66:66")

        # Scenario 2 Nodes: Email Gateway Communication
        self.email_victim = Device(name="Victim (Abdullah)", ip="10.0.0.50", mac="11:22:33:44:55:66", role="Client")
        self.router = Router(name="Gateway Router", ip="10.0.0.1", mac="AA:BB:CC:DD:EE:01")
        self.mail_server = Device(name="Corporate Mail Server (Umer)", ip="10.0.0.254", mac="99:88:77:66:55:44", role="Mail Server")
        self.s2_attacker = Attacker(name="Attacker (Anonymous)", ip="10.0.0.99", mac="DE:AD:BE:EF:77:77")

        self.packets: List[Packet] = []
        self.alerts: List[Dict[str, Any]] = []

        self.setup_baseline_network()

    def setup_baseline_network(self) -> None:
        """Sets up authentic baseline ARP tables for both network scenarios."""
        # Scenario 1 Baseline Configuration
        self.comp_a.update_arp_entry(self.comp_b.ip, self.comp_b.mac, is_baseline=True)
        self.comp_a.update_arp_entry(self.s1_attacker.ip, self.s1_attacker.mac, is_baseline=True)

        self.comp_b.update_arp_entry(self.comp_a.ip, self.comp_a.mac, is_baseline=True)
        self.comp_b.update_arp_entry(self.s1_attacker.ip, self.s1_attacker.mac, is_baseline=True)

        self.s1_attacker.update_arp_entry(self.comp_a.ip, self.comp_a.mac, is_baseline=True)
        self.s1_attacker.update_arp_entry(self.comp_b.ip, self.comp_b.mac, is_baseline=True)
        self.s1_attacker.is_poisoning = False

        # Scenario 2 Baseline Configuration
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
        """Increments and returns trigger counter to refresh UI animations."""
        self.trigger_count += 1
        return self.trigger_count

    # --- Scenario 1: Computer to Computer ---

    def s1_normal_communication(self, payload: str = "Hello Umer! Secret code: 9876", protocol: str = "HTTP") -> Packet:
        """Step 1: Computer A sends message directly to Computer B (Authentic Path)."""
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
        # Poison Computer A: maps Computer B IP to Attacker MAC
        self.s1_attacker.poison_target_arp(self.comp_a, self.comp_b.ip)
        # Poison Computer B: maps Computer A IP to Attacker MAC
        self.s1_attacker.poison_target_arp(self.comp_b, self.comp_a.ip)

        if self.logger:
            self.logger.log_event(
                "SCENARIO_1_ATTACK",
                f"ARP Poisoned: Computer A & B traffic redirected to Attacker MAC ({self.s1_attacker.mac})."
            )

        return self.detect_arp_anomalies()

    def s1_intercepted_communication(
        self,
        payload: str = "Hello Umer! Secret code: 9876",
        protocol: str = "HTTP",
        is_encrypted: bool = False,
        modified_payload: str = "Hello Umer! TRANSFER $10,000 to Anonymous Account #666"
    ) -> Packet:
        """Step 3 & 4: Message from Computer A is routed through Attacker before reaching B."""
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
            # TLS Encryption protects payload integrity
            packet.record_hop(self.comp_b.name)
            packet.status = "Intercepted (Encrypted - TLS Protected)"
            if self.logger:
                self.logger.log_event("SCENARIO_1_SECURITY", f"Packet {packet.id} intercepted but unreadable due to SSL/TLS.")
        else:
            # Plaintext payload read and altered in transit
            packet.tamper_payload(modified_payload, self.s1_attacker.name)
            packet.record_hop(self.comp_b.name)
            if self.logger:
                self.logger.log_event("SCENARIO_1_ATTACK", f"Packet {packet.id} intercepted and payload altered by Attacker!")

        self.packets.append(packet)
        if self.logger:
            self.logger.log_packet(packet.to_dict())

        return packet

    def s1_restore_arp(self) -> None:
        """Step 5: Restores authentic ARP entries for Scenario 1 devices."""
        self.s1_attacker.restore_target_arp(self.comp_a, self.comp_b.ip, self.comp_b.mac)
        self.s1_attacker.restore_target_arp(self.comp_b, self.comp_a.ip, self.comp_a.mac)
        self.s1_attacker.is_poisoning = False

        if self.logger:
            self.logger.log_event("SCENARIO_1_MITIGATION", "Authentic ARP cache restored for Scenario 1.")

    # --- Scenario 2: Email Gateway Hijacking ---

    def s2_normal_email(
        self,
        subject: str = "Q3 Financial Payroll Report",
        body: str = "Please process bonus payments for dev team.",
        sender: str = "abdullah@company.com",
        recipient: str = "umer@company.com",
        protocol: str = "SMTP"
    ) -> Packet:
        """Step 1: Outbound email routed through Gateway Router (Normal Flow)."""
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
        """Step 2: Attacker poisons Victim ARP table by impersonating Gateway Router."""
        self.s2_attacker.poison_target_arp(self.email_victim, self.router.ip)

        if self.logger:
            self.logger.log_event(
                "SCENARIO_2_ATTACK",
                f"Gateway Spoof Active: Victim ({self.email_victim.ip}) Gateway ARP redirected to Attacker ({self.s2_attacker.mac})."
            )

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
        """Step 3 & 4: Outbound email intercepted by Attacker impersonating Gateway Router."""
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
            # SMTPS/TLS encryption active
            packet.record_hop(self.router.name)
            packet.record_hop(self.mail_server.name)
            packet.status = "Intercepted (Encrypted SMTPS - TLS Protected)"
            if self.logger:
                self.logger.log_event("SCENARIO_2_SECURITY", f"Email {packet.id} intercepted at gateway but unreadable due to SMTPS/TLS.")
        else:
            # Plaintext SMTP email hijacked and payload altered
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
        """Step 5: Restores Gateway ARP entry for Scenario 2."""
        self.s2_attacker.restore_target_arp(self.email_victim, self.router.ip, self.router.mac)
        self.s2_attacker.is_poisoning = False

        if self.logger:
            self.logger.log_event("SCENARIO_2_MITIGATION", "Authentic Gateway ARP cache restored for Scenario 2.")

    # --- Anomaly Detection ---

    def detect_arp_anomalies(self) -> List[Dict[str, Any]]:
        """
        Scans device ARP tables for conflicting MAC bindings.
        Raises critical alerts when an untrusted MAC claims a target IP address.
        """
        new_alerts = []

        # Check Scenario 1 Poisoning State
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

        # Check Scenario 2 Poisoning State
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
        """Resets all simulation states, devices, packet buffers, and logs."""
        self.packets.clear()
        self.alerts.clear()
        self.trigger_count = 0
        self.s1_attacker.captured_count = 0
        self.s2_attacker.captured_count = 0
        self.setup_baseline_network()

        if self.logger:
            self.logger.clear_all_logs()
