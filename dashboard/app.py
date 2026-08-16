"""
dashboard/app.py - Streamlit Interactive UI for SilentSnare MITM Attack Simulation & Detection.
"""

import sys
import os
import streamlit as st
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# Add parent directory to sys.path to allow core and data imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.simulator import SimulatorEngine
from data.logs import EventLogger

# Streamlit Page Config
st.set_page_config(
    page_title="SilentSnare - MITM Attack Simulation System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber-Security Dark Theme CSS
CUSTOM_CSS = """
<style>
    /* Global Styles */
    .stApp {
        background-color: #0b0e14;
        color: #e2e8f0;
    }
    
    /* Header Styling */
    .title-banner {
        background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 50%, #311b92 100%);
        border: 1px solid #4338ca;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(99, 102, 241, 0.15);
    }
    
    .title-banner h1 {
        color: #6366f1;
        margin: 0;
        font-family: 'Inter', sans-serif;
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    
    .title-banner p {
        color: #94a3b8;
        margin-top: 6px;
        margin-bottom: 0;
        font-size: 1.05rem;
    }

    /* Metric Cards */
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    .metric-card h3 {
        color: #8b949e;
        font-size: 0.85rem;
        text-transform: uppercase;
        margin-bottom: 4px;
    }
    .metric-card p {
        color: #58a6ff;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0;
    }

    /* Status Badges */
    .badge-active {
        background-color: #7f1d1d;
        color: #f87171;
        border: 1px solid #ef4444;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        display: inline-block;
    }
    .badge-inactive {
        background-color: #064e3b;
        color: #34d399;
        border: 1px solid #10b981;
        padding: 4px 12px;
        border-radius: 20px;
        font-weight: 700;
        display: inline-block;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_logger():
    return EventLogger("data/silentsnare.db")


logger = get_logger()

# Initialize SimulatorEngine in session state
if "simulator" not in st.session_state:
    st.session_state.simulator = SimulatorEngine(logger=logger)

sim: SimulatorEngine = st.session_state.simulator

# Header Banner
st.markdown("""
<div class="title-banner">
    <h1>🛡️ SilentSnare: MITM Attack Simulation & Detection Platform</h1>
    <p>Educational interactive environment modeling ARP Cache Poisoning, Man-in-the-Middle packet inspection, payload modification, and TLS/SSL security validation.</p>
</div>
""", unsafe_allow_html=True)


# Sidebar Controls
st.sidebar.title("🎮 Attack Control Panel")

attacker_dev = sim.devices["attacker"]
is_poisoning = attacker_dev.is_poisoning

# Attack Toggle Button
st.sidebar.subheader("ARP Poisoning Status")
if is_poisoning:
    st.sidebar.markdown('<div class="badge-active">⚠️ ATTACK ACTIVE (ARP POISONED)</div>', unsafe_allow_html=True)
    if st.sidebar.button("🛑 Terminate Attack (Restore ARP)", use_container_width=True):
        sim.stop_arp_spoof()
        st.rerun()
else:
    st.sidebar.markdown('<div class="badge-inactive">🛡️ CLEAN (NORMAL ROUTING)</div>', unsafe_allow_html=True)
    if st.sidebar.button("⚔️ Launch ARP Spoofing Attack", use_container_width=True):
        sim.start_arp_spoof()
        st.rerun()

st.sidebar.divider()

# Attacker Configuration
st.sidebar.subheader("Attacker Behavior Mode")
intercept_mode = st.sidebar.radio(
    "Select Interception Mode:",
    options=["tamper", "passive", "drop"],
    format_func=lambda x: {
        "tamper": "✏️ Active Modification (Payload Tamper)",
        "passive": "👁️ Passive Eavesdropping (Sniff Only)",
        "drop": "🚫 Denial of Service (Drop Packets)"
    }[x],
    index=["tamper", "passive", "drop"].index(attacker_dev.intercept_mode)
)
attacker_dev.intercept_mode = intercept_mode

st.sidebar.divider()
if st.sidebar.button("🗑️ Clear Database Logs"):
    logger.clear_all_logs()
    sim.packets.clear()
    sim.alerts.clear()
    st.sidebar.success("Database logs wiped!")
    st.rerun()


# Top Metrics Summary Row
col_m1, col_m2, col_m3, col_m4 = st.columns(4)
with col_m1:
    st.markdown(f"""
    <div class="metric-card">
        <h3>Network State</h3>
        <p style="color: {'#ef4444' if is_poisoning else '#10b981'};">{'POISONED' if is_poisoning else 'SECURE'}</p>
    </div>
    """, unsafe_allow_html=True)

with col_m2:
    st.markdown(f"""
    <div class="metric-card">
        <h3>Packets Intercepted</h3>
        <p style="color: #6366f1;">{attacker_dev.captured_packets_count}</p>
    </div>
    """, unsafe_allow_html=True)

with col_m3:
    st.markdown(f"""
    <div class="metric-card">
        <h3>IDS Security Alerts</h3>
        <p style="color: {'#f59e0b' if len(sim.alerts) > 0 else '#10b981'};">{len(sim.alerts)}</p>
    </div>
    """, unsafe_allow_html=True)

with col_m4:
    st.markdown(f"""
    <div class="metric-card">
        <h3>Attacker Mode</h3>
        <p style="color: #ec4899; font-size: 1.3rem; margin-top: 8px;">{attacker_dev.intercept_mode.upper()}</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Main Content Tabs
tab_topo, tab_console, tab_inspect, tab_alerts = st.tabs([
    "🕸️ Network Topology & ARP Tables",
    "⚡ Packet Transmission Console",
    "🔍 Packet Inspector & Encryption Analysis",
    "🚨 IDS Alerts & Operational Logs"
])

# ---------------------------------------------------------
# TAB 1: Network Topology & ARP Tables
# ---------------------------------------------------------
with tab_topo:
    st.subheader("Simulated Network Topology & Traffic Flow")
    
    col_graph, col_arp = st.columns([3, 2])
    
    with col_graph:
        # Generate Network Diagram with NetworkX
        fig, ax = plt.subplots(figsize=(7, 4.5))
        fig.patch.set_facecolor('#0f172a')
        ax.set_facecolor('#0f172a')
        
        G = nx.DiGraph()
        pos = {
            "Victim Client (Alice)": (0, 1),
            "Gateway Router": (1, 1),
            "Email Gateway (Bob)": (2, 1),
            "SilentSnare Attacker": (0.5, 0)
        }
        
        for node in pos:
            G.add_node(node)
            
        colors = []
        for node in G.nodes():
            if "Attacker" in node:
                colors.append('#ef4444' if is_poisoning else '#64748b')
            elif "Gateway Router" in node:
                colors.append('#3b82f6')
            else:
                colors.append('#10b981')
                
        nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=2200, ax=ax)
        nx.draw_networkx_labels(G, pos, font_color='white', font_weight='bold', font_size=8, ax=ax)
        
        if is_poisoning:
            # Poisoned traffic path
            edges_to_draw = [
                ("Victim Client (Alice)", "SilentSnare Attacker"),
                ("SilentSnare Attacker", "Gateway Router"),
                ("Gateway Router", "Email Gateway (Bob)")
            ]
            nx.draw_networkx_edges(G, pos, edgelist=edges_to_draw, edge_color='#ef4444', width=2.5, arrowsize=18, ax=ax)
        else:
            # Normal traffic path
            edges_to_draw = [
                ("Victim Client (Alice)", "Gateway Router"),
                ("Gateway Router", "Email Gateway (Bob)")
            ]
            nx.draw_networkx_edges(G, pos, edgelist=edges_to_draw, edge_color='#10b981', width=2.5, arrowsize=18, ax=ax)
            
        plt.title("Live Traffic Flow Diagram", color='#94a3b8', fontsize=12)
        plt.axis('off')
        st.pyplot(fig, use_container_width=True)
        
    with col_arp:
        st.subheader("Live ARP Cache Inspection")
        st.caption("Inspect local IP-to-MAC resolution tables across LAN endpoints.")
        
        arp_records = []
        for name, dev in sim.devices.items():
            for target_ip, mac_addr in dev.arp_table.items():
                is_compromised = (name == "victim_client" and target_ip == sim.devices["router"].ip and mac_addr == attacker_dev.mac)
                arp_records.append({
                    "Device": dev.hostname,
                    "Target IP": target_ip,
                    "Resolved MAC": mac_addr,
                    "Status": "⚠️ POISONED" if is_compromised else "AUTHENTIC"
                })
        
        df_arp = pd.DataFrame(arp_records)
        st.dataframe(df_arp, use_container_width=True, hide_index=True)


# ---------------------------------------------------------
# TAB 2: Packet Transmission Console
# ---------------------------------------------------------
with tab_console:
    st.subheader("Transmit Test Packets Across LAN")
    
    col_p1, col_p2 = st.columns([1, 1])
    
    with col_p1:
        st.write("##### Configure Packet Settings")
        
        preset_choice = st.selectbox(
            "Quick Presets:",
            options=[
                "Unsecured HTTP Login (Plaintext)",
                "Secured HTTPS Login (SSL/TLS Encrypted)",
                "Unsecured SMTP Email Payload",
                "Custom Payload"
            ]
        )
        
        if preset_choice == "Unsecured HTTP Login (Plaintext)":
            default_proto = "HTTP"
            default_payload = "POST /login credentials=user123:Password123!"
            default_encrypted = False
        elif preset_choice == "Secured HTTPS Login (SSL/TLS Encrypted)":
            default_proto = "HTTPS"
            default_payload = "POST /api/v1/auth bearer_token=eyJhbGciOiJIUzI1Ni..."
            default_encrypted = True
        elif preset_choice == "Unsecured SMTP Email Payload":
            default_proto = "SMTP"
            default_payload = "MAIL FROM:<alice@company.com> BODY: Confidential Q3 financial draft."
            default_encrypted = False
        else:
            default_proto = "HTTP"
            default_payload = "Hello World Payload"
            default_encrypted = False

        protocol = st.text_input("Protocol:", value=default_proto)
        payload_text = st.text_area("Payload Data:", value=default_payload, height=100)
        is_encrypted_flag = st.checkbox("🔒 Enable SSL/TLS Encryption (HTTPS)", value=default_encrypted)
        
        if st.button("🚀 Transmit Packet Now", type="primary", use_container_width=True):
            pkt = sim.send_packet(
                src_key="victim_client",
                dst_key="victim_server",
                protocol=protocol,
                payload=payload_text,
                is_encrypted=is_encrypted_flag
            )
            st.success(f"Packet {pkt.id} transmitted! Status: {pkt.status}")
            st.rerun()

    with col_p2:
        st.write("##### Last Transmitted Packet Result")
        if sim.packets:
            last_pkt = sim.packets[-1]
            
            st.info(f"**Packet ID:** `{last_pkt.id}` | **Time:** `{last_pkt.timestamp}`")
            st.write(f"**Route Hops:** `{' -> '.join(last_pkt.hop_history)}`")
            st.write(f"**Transmission Status:** `{last_pkt.status}`")
            
            if last_pkt.is_encrypted:
                st.markdown("🔒 **Security Note:** SSL/TLS encryption prevented payload reading or alteration.")
            elif last_pkt.is_tampered:
                st.error("⚠️ **MITM Alteration Detected:** Payload was modified in-transit!")
                st.code(f"Original: {last_pkt.original_payload}\nModified: {last_pkt.payload}", language="text")
            else:
                st.write("**Payload Delivered:**")
                st.code(last_pkt.payload, language="text")
        else:
            st.write("No packets transmitted yet in this session.")


# ---------------------------------------------------------
# TAB 3: Packet Inspector & Encryption Analysis
# ---------------------------------------------------------
with tab_inspect:
    st.subheader("Captured Packet Logs & Comparative Security Analysis")
    
    st.markdown("""
    > **Educational Context:** Compare how unencrypted protocols (HTTP/SMTP) allow full MITM inspection and payload modification, whereas secured protocols (HTTPS/TLS) protect data confidentiality.
    """)
    
    db_packets = logger.get_packets()
    if db_packets:
        df_pkts = pd.DataFrame(db_packets)
        
        st.dataframe(
            df_pkts[["id", "timestamp", "protocol", "src_ip", "dst_ip", "status", "is_encrypted", "is_tampered", "payload"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No captured packet history found in database.")


# ---------------------------------------------------------
# TAB 4: IDS Alerts & Operational Logs
# ---------------------------------------------------------
with tab_alerts:
    st.subheader("Real-Time Intrusion Detection System (IDS) Alerts")
    
    alerts = logger.get_alerts()
    if alerts:
        for al in alerts:
            st.error(f"🚨 **[{al['timestamp']}] {al['type']} (Severity: {al['severity']})**")
            st.write(f"**Details:** {al['details']}")
            st.write(f"**Recommended Countermeasure:** `{al['recommendation']}`")
            st.divider()
    else:
        st.success("✅ No ARP Poisoning anomalies currently flagged by IDS.")
        
    st.subheader("System Event Log")
    events = logger.get_events()
    if events:
        df_events = pd.DataFrame(events)
        st.dataframe(df_events[["timestamp", "category", "message"]], use_container_width=True, hide_index=True)
