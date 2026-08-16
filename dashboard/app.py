"""
dashboard/app.py - Streamlit Interactive UI for SilentSnare MITM Simulation.
Features dual scenarios, before/after ARP table comparisons, and an animated SVG packet path.
"""

import sys
import os
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

# Add parent directory to path to import core and data modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.simulator import SimulatorEngine
from data.logs import EventLogger

# Page Configuration
st.set_page_config(
    page_title="SilentSnare - MITM Simulation Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark Theme CSS
CUSTOM_CSS = """
<style>
    .stApp {
        background-color: #0b0e14;
        color: #e2e8f0;
    }
    .main-banner {
        background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #311b92 100%);
        border: 1px solid #4338ca;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(99, 102, 241, 0.2);
    }
    .main-banner h1 {
        color: #818cf8;
        font-family: 'Inter', sans-serif;
        font-weight: 800;
        margin: 0 0 6px 0;
        font-size: 2.2rem;
    }
    .main-banner p {
        color: #94a3b8;
        margin: 0;
        font-size: 1.05rem;
    }
    .card-box {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 16px;
        margin-bottom: 16px;
    }
    .badge-poisoned {
        background-color: #7f1d1d;
        color: #f87171;
        border: 1px solid #ef4444;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-authentic {
        background-color: #064e3b;
        color: #34d399;
        border: 1px solid #10b981;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 700;
        font-size: 0.85rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_logger():
    return EventLogger("data/silentsnare.db")


logger = get_logger()

if "sim" not in st.session_state:
    st.session_state.sim = SimulatorEngine(logger=logger)
    st.session_state.active_packet = None
    st.session_state.last_path_type = "direct"
    st.session_state.last_scenario = "s1"

sim: SimulatorEngine = st.session_state.sim

# Helper to render Animated SVG Packet Component
def render_animated_packet_diagram(scenario: str, path_type: str, is_encrypted: bool, is_tampered: bool, trigger_id: int):
    """
    Renders an HTML/SVG viewport where a glowing packet dot visibly travels
    along the path from sender -> (attacker if active) -> receiver.
    """
    # Color logic
    if is_encrypted:
        packet_color = "#FFD700"  # Gold for SSL/TLS
        glow_color = "rgba(255, 215, 0, 0.8)"
        packet_symbol = "🔒"
    elif is_tampered or path_type == "intercepted":
        packet_color = "#FF4B4B"  # Red for Intercepted/Tampered
        glow_color = "rgba(255, 75, 75, 0.8)"
        packet_symbol = "⚠️"
    else:
        packet_color = "#00F2FE"  # Cyan for Clean
        glow_color = "rgba(0, 242, 254, 0.8)"
        packet_symbol = "✉️"

    if scenario == "s1":
        # Scenario 1 Nodes
        node_a = {"label": "Computer A (Abdullah)", "x": 90, "y": 140, "color": "#10B981"}
        attacker = {"label": "Attacker (Anonymous)", "x": 300, "y": 45, "color": "#EF4444" if path_type == "intercepted" else "#64748B"}
        node_b = {"label": "Computer B (Umer)", "x": 510, "y": 140, "color": "#3B82F6"}

        if path_type == "intercepted":
            path_d = f"M {node_a['x']} {node_a['y']} L {attacker['x']} {attacker['y']} L {node_b['x']} {node_b['y']}"
            line_color = "#EF4444"
        else:
            path_d = f"M {node_a['x']} {node_a['y']} L {node_b['x']} {node_b['y']}"
            line_color = "#10B981"

        nodes_xml = f"""
            <circle cx="{node_a['x']}" cy="{node_a['y']}" r="26" fill="{node_a['color']}" />
            <text x="{node_a['x']}" y="{node_a['y']+42}" text-anchor="middle" fill="#FFFFFF" font-size="12" font-weight="bold">{node_a['label']}</text>

            <circle cx="{attacker['x']}" cy="{attacker['y']}" r="26" fill="{attacker['color']}" />
            <text x="{attacker['x']}" y="{attacker['y']-34}" text-anchor="middle" fill="#FFFFFF" font-size="12" font-weight="bold">{attacker['label']}</text>

            <circle cx="{node_b['x']}" cy="{node_b['y']}" r="26" fill="{node_b['color']}" />
            <text x="{node_b['x']}" y="{node_b['y']+42}" text-anchor="middle" fill="#FFFFFF" font-size="12" font-weight="bold">{node_b['label']}</text>
        """
    else:
        # Scenario 2 Nodes (Email via Gateway)
        victim = {"label": "Victim (Abdullah)", "x": 80, "y": 140, "color": "#10B981"}
        attacker = {"label": "Attacker (Anonymous)", "x": 300, "y": 40, "color": "#EF4444" if path_type == "intercepted" else "#64748B"}
        router = {"label": "Gateway Router", "x": 300, "y": 210, "color": "#3B82F6"}
        server = {"label": "Mail Server (Umer)", "x": 520, "y": 140, "color": "#8B5CF6"}

        if path_type == "intercepted":
            path_d = f"M {victim['x']} {victim['y']} L {attacker['x']} {attacker['y']} L {router['x']} {router['y']} L {server['x']} {server['y']}"
            line_color = "#EF4444"
        else:
            path_d = f"M {victim['x']} {victim['y']} L {router['x']} {router['y']} L {server['x']} {server['y']}"
            line_color = "#10B981"

        nodes_xml = f"""
            <circle cx="{victim['x']}" cy="{victim['y']}" r="24" fill="{victim['color']}" />
            <text x="{victim['x']}" y="{victim['y']+40}" text-anchor="middle" fill="#FFFFFF" font-size="11" font-weight="bold">{victim['label']}</text>

            <circle cx="{attacker['x']}" cy="{attacker['y']}" r="24" fill="{attacker['color']}" />
            <text x="{attacker['x']}" y="{attacker['y']-32}" text-anchor="middle" fill="#FFFFFF" font-size="11" font-weight="bold">{attacker['label']}</text>

            <circle cx="{router['x']}" cy="{router['y']}" r="24" fill="{router['color']}" />
            <text x="{router['x']}" y="{router['y']+38}" text-anchor="middle" fill="#FFFFFF" font-size="11" font-weight="bold">{router['label']}</text>

            <circle cx="{server['x']}" cy="{server['y']}" r="24" fill="{server['color']}" />
            <text x="{server['x']}" y="{server['y']+40}" text-anchor="middle" fill="#FFFFFF" font-size="11" font-weight="bold">{server['label']}</text>
        """

    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                margin: 0;
                background-color: #0d1117;
                font-family: 'Inter', sans-serif;
                overflow: hidden;
            }}
            .svg-container {{
                width: 100%;
                height: 290px;
                display: flex;
                justify-content: center;
                align-items: center;
            }}
            .path-line {{
                stroke: {line_color};
                stroke-width: 3;
                stroke-dasharray: 6;
                animation: dash 20s linear infinite;
            }}
            @keyframes dash {{
                to {{ stroke-dashoffset: -1000; }}
            }}
            .packet-dot {{
                fill: {packet_color};
                filter: drop-shadow(0px 0px 8px {glow_color});
            }}
        </style>
    </head>
    <body>
        <div class="svg-container">
            <svg width="600" height="280" viewBox="0 0 600 280">
                <!-- Background Connection Path -->
                <path id="anim-path-{trigger_id}" class="path-line" d="{path_d}" fill="none" />
                
                <!-- Network Nodes -->
                {nodes_xml}

                <!-- Traveling Packet Icon -->
                <g>
                    <circle r="12" class="packet-dot">
                        <animateMotion 
                            path="{path_d}" 
                            dur="1.8s" 
                            repeatCount="1" 
                            fill="freeze" 
                            calcMode="linear" />
                    </circle>
                    <text font-size="10" text-anchor="middle" dy="4" fill="#000000">
                        {packet_symbol}
                        <animateMotion path="{path_d}" dur="1.8s" repeatCount="1" fill="freeze" calcMode="linear" />
                    </text>
                </g>
            </svg>
        </div>
    </body>
    </html>
    """
    components.html(html_code, height=300)


# Title Banner
st.markdown("""
<div class="main-banner">
    <h1>🛡️ SilentSnare: Educational MITM Attack Simulation</h1>
    <p>Pure software simulation demonstrating ARP Cache Poisoning, Packet Interception, Payload Alteration, and SSL/TLS Security Protections.</p>
</div>
""", unsafe_allow_html=True)


# Sidebar Configuration
st.sidebar.title("🎛️ Session Controls")

if st.sidebar.button("🔄 Reset Entire Simulation", use_container_width=True):
    sim.reset_all()
    st.session_state.active_packet = None
    st.session_state.last_path_type = "direct"
    st.sidebar.success("Simulation & ARP caches reset to baseline!")
    st.rerun()

st.sidebar.divider()
st.sidebar.markdown("### 📊 Live Statistics")
st.sidebar.write(f"**Total Packets Sent:** `{len(sim.packets)}`")
st.sidebar.write(f"**S1 Packets Intercepted:** `{sim.s1_attacker.captured_count}`")
st.sidebar.write(f"**S2 Packets Intercepted:** `{sim.s2_attacker.captured_count}`")
st.sidebar.write(f"**IDS Alerts Fired:** `{len(sim.alerts)}`")


# Main Tabs (Scenario 1 & Scenario 2)
tab1, tab2, tab_logs = st.tabs([
    "💻 Scenario 1: MITM Between Two Computers",
    "📧 Scenario 2: Email Gateway Hijacking",
    "📜 Session Event Logs & Database"
])

# =====================================================================
# TAB 1: Scenario 1 - MITM Between Two Computers
# =====================================================================
with tab1:
    st.subheader("Scenario 1: Man-in-the-Middle Between Computer A & Computer B")
    st.caption("Step through the attack lifecycle to see how ARP spoofing redirects traffic through the Attacker.")

    # Control Buttons Row
    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        if st.button("1️⃣ Normal Direct Packet", use_container_width=True):
            st.session_state.active_packet = sim.s1_normal_communication(
                payload="Hello Umer! Secret Passcode: 9876",
                protocol="HTTP"
            )
            st.session_state.last_path_type = "direct"
            st.session_state.last_scenario = "s1"
            st.rerun()

    with c2:
        if st.button("2️⃣ Execute ARP Spoofing", use_container_width=True):
            alerts = sim.s1_arp_spoof()
            st.session_state.last_scenario = "s1"
            if alerts:
                st.toast("🚨 IDS Alert: ARP Cache Poisoning Detected!", icon="⚠️")
            st.rerun()

    with c3:
        if st.button("3️⃣ Intercept & Modify Message", use_container_width=True):
            st.session_state.active_packet = sim.s1_intercepted_communication(
                payload="Hello Umer! Secret Passcode: 9876",
                protocol="HTTP",
                is_encrypted=False,
                modified_payload="Hello Umer! TRANSFER $10,000 to Anonymous Account #666"
            )
            st.session_state.last_path_type = "intercepted"
            st.session_state.last_scenario = "s1"
            st.rerun()

    with c4:
        if st.button("4️⃣ Send SSL/TLS Encrypted", use_container_width=True):
            st.session_state.active_packet = sim.s1_intercepted_communication(
                payload="Hello Umer! Secret Passcode: 9876",
                protocol="HTTPS",
                is_encrypted=True
            )
            st.session_state.last_path_type = "intercepted"
            st.session_state.last_scenario = "s1"
            st.rerun()

    with c5:
        if st.button("5️⃣ Restore Clean ARP", use_container_width=True):
            sim.s1_restore_arp()
            st.session_state.last_path_type = "direct"
            st.session_state.last_scenario = "s1"
            st.success("Authentic ARP tables restored for Computer A & B!")
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Animated Visualization Component
    col_vis, col_pkt = st.columns([3, 2])

    with col_vis:
        st.write("##### 🎞️ Real-Time Packet Path Animation")
        pkt = st.session_state.active_packet
        is_enc = pkt.is_encrypted if pkt else False
        is_tam = pkt.is_tampered if pkt else False
        path_t = st.session_state.last_path_type
        
        render_animated_packet_diagram(
            scenario="s1",
            path_type=path_t,
            is_encrypted=is_enc,
            is_tampered=is_tam,
            trigger_id=sim.trigger_count
        )

    with col_pkt:
        st.write("##### 🔍 Active Packet Detail View")
        if pkt and pkt.scenario_type == "computer_mitm":
            st.markdown(f"""
            <div class="card-box">
                <p><b>Packet ID:</b> <code>{pkt.id}</code> | <b>Timestamp:</b> <code>{pkt.timestamp}</code></p>
                <p><b>Protocol:</b> <code>{pkt.protocol}</code> | <b>Encrypted:</b> {'🔒 YES (TLS)' if pkt.is_encrypted else '🔓 NO (Plaintext)'}</p>

            <p><b>Route Hops:</b> <code>{' ➔ '.join(pkt.hop_history)}</code></p>
                <p><b>Status:</b> <code>{pkt.status}</code></p>
            </div>
            """, unsafe_allow_html=True)

            if pkt.is_encrypted:
                st.warning("🔒 **SSL/TLS Security Active:** Attacker intercepted packet frame, but payload is encrypted ciphertext and unreadable.")
                st.code(pkt.get_display_content(), language="text")
            elif pkt.is_tampered:
                st.error("⚠️ **MITM Alteration Alert:** Attacker read and modified plaintext payload!")
                st.code(f"Original: {pkt.original_payload}\nAltered:  {pkt.payload}", language="text")
            else:
                st.success("✅ **Clean Payload Received:**")
                st.code(pkt.payload, language="text")
        else:
            st.info("Click an action button above to trigger packet transmission.")

    st.divider()

    # Before & After ARP Table Comparison
    st.subheader("📋 ARP Table State (Before vs After Spoofing)")
    col_arp_a, col_arp_b = st.columns(2)

    with col_arp_a:
        st.write("##### Computer A ARP Cache")
        df_arp_a = pd.DataFrame(sim.comp_a.get_arp_comparison())
        st.dataframe(df_arp_a, use_container_width=True, hide_index=True)

    with col_arp_b:
        st.write("##### Computer B ARP Cache")
        df_arp_b = pd.DataFrame(sim.comp_b.get_arp_comparison())
        st.dataframe(df_arp_b, use_container_width=True, hide_index=True)


# =====================================================================
# TAB 2: Scenario 2 - Email Gateway Hijacking
# =====================================================================
with tab2:
    st.subheader("Scenario 2: Email Hijacking via Gateway Spoofing")
    st.caption("Demonstrates how poisoning a victim's Gateway Router ARP entry allows the Attacker to intercept outbound emails.")

    # Control Buttons Row
    e1, e2, e3, e4, e5 = st.columns(5)

    with e1:
        if st.button("1️⃣ Normal Email Flow", use_container_width=True):
            st.session_state.active_packet = sim.s2_normal_email(
                subject="Q3 Payroll Draft",
                body="Please disburse $50,000 team bonus.",
                sender="abdullah@company.com",
                recipient="umer@company.com"
            )
            st.session_state.last_path_type = "direct"
            st.session_state.last_scenario = "s2"
            st.rerun()

    with e2:
        if st.button("2️⃣ Spoof Gateway ARP", use_container_width=True):
            alerts = sim.s2_gateway_spoof()
            st.session_state.last_scenario = "s2"
            if alerts:
                st.toast("🚨 IDS Alert: Gateway Impersonation Detected!", icon="⚠️")
            st.rerun()

    with e3:
        if st.button("3️⃣ Intercept & Alter Email", use_container_width=True):
            st.session_state.active_packet = sim.s2_intercepted_email(
                subject="Q3 Payroll Draft",
                body="Please disburse $50,000 team bonus.",
                sender="abdullah@company.com",
                recipient="umer@company.com",
                protocol="SMTP",
                is_encrypted=False,
                modified_body="HIJACKED BY ANONYMOUS: Wire $50,000 funds to offshore account #998877!"
            )
            st.session_state.last_path_type = "intercepted"
            st.session_state.last_scenario = "s2"
            st.rerun()

    with e4:
        if st.button("4️⃣ Send SMTPS Encrypted Email", use_container_width=True):
            st.session_state.active_packet = sim.s2_intercepted_email(
                subject="Q3 Payroll Draft",
                body="Please disburse $50,000 team bonus.",
                sender="abdullah@company.com",
                recipient="umer@company.com",
                protocol="SMTPS",
                is_encrypted=True
            )
            st.session_state.last_path_type = "intercepted"
            st.session_state.last_scenario = "s2"
            st.rerun()

    with e5:
        if st.button("5️⃣ Restore Gateway ARP", use_container_width=True):
            sim.s2_restore_arp()
            st.session_state.last_path_type = "direct"
            st.session_state.last_scenario = "s2"
            st.success("Authentic Gateway ARP restored!")
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    # Animated Email Viewport
    col_e_vis, col_e_pkt = st.columns([3, 2])

    with col_e_vis:
        st.write("##### 🎞️ Email Gateway Routing Animation")
        pkt_e = st.session_state.active_packet
        is_enc_e = pkt_e.is_encrypted if pkt_e else False
        is_tam_e = pkt_e.is_tampered if pkt_e else False
        path_t_e = st.session_state.last_path_type

        render_animated_packet_diagram(
            scenario="s2",
            path_type=path_t_e,
            is_encrypted=is_enc_e,
            is_tampered=is_tam_e,
            trigger_id=sim.trigger_count
        )

    with col_e_pkt:
        st.write("##### 📧 Email Packet Inspection")
        if pkt_e and pkt_e.scenario_type == "email_gateway":
            st.markdown(f"""
            <div class="card-box">
                <p><b>Email Subject:</b> <code>{pkt_e.email_subject}</code></p>
                <p><b>Protocol:</b> <code>{pkt_e.protocol}</code> | <b>Encrypted:</b> {'🔒 YES (SMTPS/TLS)' if pkt_e.is_encrypted else '🔓 NO (SMTP Plaintext)'}</p>
                <p><b>Route Hops:</b> <code>{' ➔ '.join(pkt_e.hop_history)}</code></p>
                <p><b>Status:</b> <code>{pkt_e.status}</code></p>
            </div>
            """, unsafe_allow_html=True)

            if pkt_e.is_encrypted:
                st.warning("🔒 **SMTPS Security Active:** Gateway Attacker intercepted packet, but SMTPS/TLS encryption blocked email reading & body alteration.")
                st.code(pkt_e.get_display_content(), language="text")
            elif pkt_e.is_tampered:
                st.error("⚠️ **Email Body Hijacked:** Attacker altered email contents in-transit!")
                st.code(f"Original Email: {pkt_e.original_payload}\nAltered Email:  {pkt_e.payload}", language="text")
            else:
                st.success("✅ **Clean Email Delivered to Mail Server:**")
                st.code(pkt_e.payload, language="text")
        else:
            st.info("Click an action button above to transmit an email packet.")

    st.divider()

    # Victim Gateway ARP Cache Inspection
    st.subheader("📋 Victim Gateway ARP Cache State (Before vs After)")
    df_arp_victim = pd.DataFrame(sim.email_victim.get_arp_comparison())
    st.dataframe(df_arp_victim, use_container_width=True, hide_index=True)


# =====================================================================
# TAB 3: Session Event Logs & Database
# =====================================================================
with tab_logs:
    st.subheader("📜 Live Event Logs & Security Audit History")

    # IDS Alerts Section
    st.write("##### 🚨 Intrusion Detection System (IDS) Alerts")
    alerts_list = logger.get_alerts()
    if alerts_list:
        for al in alerts_list:
            st.error(f"**[{al['timestamp']}] {al['type']} (Severity: {al['severity']})**")
            st.write(f"• **Details:** {al['details']}")
            st.write(f"• **Countermeasure:** `{al['recommendation']}`")
            st.divider()
    else:
        st.success("✅ No security alerts detected.")

    st.write("##### 📦 All Captured Session Packets")
    pkt_list = logger.get_packets()
    if pkt_list:
        df_p = pd.DataFrame(pkt_list)
        st.dataframe(
            df_p[["id", "timestamp", "scenario_type", "protocol", "sender", "receiver", "status", "is_encrypted", "is_tampered", "display_payload"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No packets captured yet in this session.")

    st.write("##### ⚙️ System Operational Logs")
    events_list = logger.get_events()
    if events_list:
        df_ev = pd.DataFrame(events_list)
        st.dataframe(df_ev[["timestamp", "category", "message"]], use_container_width=True, hide_index=True)
