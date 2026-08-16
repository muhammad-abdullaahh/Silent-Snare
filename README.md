# 🛡️ SilentSnare: Man-in-the-Middle (MITM) Simulation & Security Inspection Platform

SilentSnare is an interactive, pure software network simulation platform built with **Python** and **Streamlit**. It demonstrates the mechanics of **ARP Cache Poisoning**, **Man-in-the-Middle (MITM) Packet Interception**, **Payload Alteration**, and the defensive capabilities of **SSL/TLS Encryption (HTTPS & SMTPS)**.

---

## 🌟 Key Features

- **🎞️ Real-Time Animated SVG Topology**: Visually animates packet flow across network nodes (`✉️` / `📧`), radiating red ARP poison waves (`⚡`), TLS shield bubbles (`🔒`), and payload tampering alerts (`⚠️`).
- **💬 Custom Message Composer**: Type custom messages or emails to test live transmission, payload modification, and encryption behavior.
- **📊 Side-by-Side Message & Encryption Inspector**: 3-stage visual breakdown inspecting:
  1. **Sender Box**: Original plaintext payload emitted by client.
  2. **Network & TLS Encryption Box**: Protocol, cipher suite (`AES-256-GCM`), RSA key exchange, and actual in-transit **Hex Ciphertext Blob** sniffed by the attacker.
  3. **Recipient Box**: Private key decryption (`D_k`), tampered payload alerts, or clean delivery confirmation.
- **🔀 Dual Network Scenarios**:
  - **Scenario 1 (Computer A ➔ Computer B)**: Direct P2P communication hijacked via bidirectional ARP spoofing.
  - **Scenario 2 (Email Gateway Hijacking)**: Outbound SMTP email traffic hijacked by impersonating the default Gateway Router.
- **🚨 IDS Anomaly Detection**: Intrusion Detection System engine continuously monitors ARP tables for duplicate MAC address bindings and raises critical alerts with mitigation recommendations.
- **📜 SQLite Audit Logger**: Persistent database logging for packet frame captures, IDS security alerts, and system audit trails.

---

## 🏗️ Project Architecture

```
SilentSnare/
├── core/
│   ├── devices.py      # NetworkDevice, Device, Router, & Attacker node models with ARP tables
│   ├── packet.py       # Simulated packet frame, routing hop history, and ciphertext renderer
│   └── simulator.py    # In-memory simulation engine & IDS anomaly detector
├── dashboard/
│   └── app.py          # Interactive Streamlit dashboard with animated SVG viewports & inspection cards
├── data/
│   ├── logs.py         # SQLite event logger & database interface
│   └── silentsnare.db  # SQLite database storing session audit logs
└── requirements.txt    # Python dependencies
```

---

## 🚀 Quick Start Guide

### 1. Prerequisites
Ensure you have Python 3.10 or higher installed:
```bash
python --version
```

### 2. Install Dependencies
Install the required packages from `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 3. Launch the Streamlit Dashboard
Run the following command from the project root directory:
```bash
streamlit run dashboard/app.py
```
*(Or via Python module execution: `python -m streamlit run dashboard/app.py`)*

Once started, open your web browser to `http://localhost:8501`.

---

## 🎮 Simulation Lifecycle Steps

### Scenario 1: MITM Between Two Computers
1. **1️⃣ Normal Direct Packet**: Sends an unencrypted HTTP message directly from Computer A to Computer B over authentic baseline ARP paths.
2. **2️⃣ Execute ARP Spoofing**: Attacker broadcasts malicious Gratuitous ARP (GARP) replies, poisoning Computer A & B cache tables. IDS triggers a **CRITICAL ARP Poisoning Alert**.
3. **3️⃣ Intercept & Modify Message**: Computer A sends a message. Traffic routes through Attacker, who reads and alters the plaintext payload in-transit before forwarding it to Computer B.
4. **4️⃣ Send SSL/TLS Encrypted**: Computer A sends traffic over HTTPS. The Attacker intercepts the network frame, but TLS encryption scrambles the payload into unreadable **AES-256-GCM Ciphertext**. Computer B successfully decrypts the payload using its Private Key.
5. **5️⃣ Restore Clean ARP**: Restores authentic baseline ARP entries for both hosts.

### Scenario 2: Email Gateway Hijacking
1. **1️⃣ Normal Email Flow**: Victim transmits an email routed through the default Gateway Router to the Corporate Mail Server.
2. **2️⃣ Spoof Gateway ARP**: Attacker poisons the Victim's ARP table by impersonating the Gateway Router MAC address.
3. **3️⃣ Intercept & Alter Email**: Outbound SMTP email routes through the Attacker, who hijacks and modifies the email body payload.
4. **4️⃣ Send SMTPS Encrypted Email**: Email sent over SMTPS/TLS. Encryption protects email confidentiality and integrity against gateway tampering.
5. **5️⃣ Restore Gateway ARP**: Restores authentic Gateway Router ARP bindings.

---

## 🛡️ Security Countermeasures & Recommendations

| Threat / Attack | Detection Signal | Mitigation Countermeasure |
| :--- | :--- | :--- |
| **ARP Cache Poisoning** | Duplicate MAC addresses associated with multiple IP entries in ARP cache. | Static ARP Tables, Dynamic ARP Inspection (DAI), 802.1X Port Security |
| **Plaintext MITM Interception** | Payload tampering & credential harvesting in-transit. | Enforce End-to-End Encryption (HTTPS, SMTPS, SSH, TLS 1.3) |
| **Gateway Impersonation** | Rogue ARP replies for Default Gateway IP address. | DHCP Snooping binding table validation with DAI |

---

## 📄 License

Distributed under the MIT License. Designed for educational cybersecurity demonstration and network security research.
