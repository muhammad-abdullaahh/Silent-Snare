import sys
import os
import hashlib
from typing import Optional, Any, Dict
import streamlit as st
import streamlit.components.v1 as components
import pandas as pd

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.simulator import SimulatorEngine
from data.logs import EventLogger

# Streamlit Page Setup
st.set_page_config(
    page_title="SilentSnare - MITM Simulation Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling for Cyber Theme
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
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_logger():
    """Returns singleton EventLogger instance."""
    return EventLogger("data/silentsnare.db")


logger = get_logger()

# Initialize Streamlit Session State
if "sim" not in st.session_state:
    st.session_state.sim = SimulatorEngine(logger=logger)
    st.session_state.active_packet = None
    st.session_state.last_path_type = "direct"
    st.session_state.last_action = "normal"
    st.session_state.last_scenario = "s1"
    st.session_state.trigger_id = 1

sim: SimulatorEngine = st.session_state.sim


def render_animated_packet_diagram(
    scenario: str,
    path_type: str,
    is_encrypted: bool,
    is_tampered: bool,
    trigger_id: int,
    action_type: str = "normal"
):
    """
    Renders the SVG diagram showing packet flows, ARP poisoning waves,
    and payload modification alerts for both network scenarios.
    """
    if scenario == "s1":
        node_a = {"label": "Computer A (Abdullah)", "x": 90, "y": 135, "color": "#10B981", "icon": "💻"}
        attacker = {"label": "Attacker (Anonymous)", "x": 300, "y": 45, "color": "#EF4444" if (path_type == "intercepted" or action_type == "spoof") else "#64748B", "icon": "🥷"}
        node_b = {"label": "Computer B (Umer)", "x": 510, "y": 135, "color": "#3B82F6", "icon": "💻"}

        direct_path = f"M {node_a['x']} {node_a['y']} L {node_b['x']} {node_b['y']}"
        intercept_path = f"M {node_a['x']} {node_a['y']} L {attacker['x']} {attacker['y']} L {node_b['x']} {node_b['y']}"
        spoof_path_1 = f"M {attacker['x']} {attacker['y']} L {node_a['x']} {node_a['y']}"
        spoof_path_2 = f"M {attacker['x']} {attacker['y']} L {node_b['x']} {node_b['y']}"

        current_path = intercept_path if (path_type == "intercepted" or action_type in ["intercept", "tls"]) else direct_path

        nodes_html = f"""
            <circle cx="{node_a['x']}" cy="{node_a['y']}" r="26" fill="{node_a['color']}" filter="url(#glow-green)" />
            <text x="{node_a['x']}" y="{node_a['y']+4}" text-anchor="middle" font-size="16">{node_a['icon']}</text>
            <text x="{node_a['x']}" y="{node_a['y']+42}" text-anchor="middle" fill="#E2E8F0" font-size="11" font-weight="bold">{node_a['label']}</text>

            <circle cx="{attacker['x']}" cy="{attacker['y']}" r="26" fill="{attacker['color']}" filter="url(#glow-red)" />
            <text x="{attacker['x']}" y="{attacker['y']+4}" text-anchor="middle" font-size="16">{attacker['icon']}</text>
            <text x="{attacker['x']}" y="{attacker['y']-34}" text-anchor="middle" fill="#E2E8F0" font-size="11" font-weight="bold">{attacker['label']}</text>

            <circle cx="{node_b['x']}" cy="{node_b['y']}" r="26" fill="{node_b['color']}" filter="url(#glow-blue)" />
            <text x="{node_b['x']}" y="{node_b['y']+4}" text-anchor="middle" font-size="16">{node_b['icon']}</text>
            <text x="{node_b['x']}" y="{node_b['y']+42}" text-anchor="middle" fill="#E2E8F0" font-size="11" font-weight="bold">{node_b['label']}</text>
        """
    else:
        victim = {"label": "Victim (Abdullah)", "x": 75, "y": 135, "color": "#10B981", "icon": "💻"}
        attacker = {"label": "Attacker (Anonymous)", "x": 290, "y": 45, "color": "#EF4444" if (path_type == "intercepted" or action_type == "spoof") else "#64748B", "icon": "🥷"}
        router = {"label": "Gateway Router", "x": 290, "y": 210, "color": "#3B82F6", "icon": "🌐"}
        server = {"label": "Mail Server (Umer)", "x": 515, "y": 135, "color": "#8B5CF6", "icon": "🖥️"}

        direct_path = f"M {victim['x']} {victim['y']} L {router['x']} {router['y']} L {server['x']} {server['y']}"
        intercept_path = f"M {victim['x']} {victim['y']} L {attacker['x']} {attacker['y']} L {router['x']} {router['y']} L {server['x']} {server['y']}"
        spoof_path_1 = f"M {attacker['x']} {attacker['y']} L {victim['x']} {victim['y']}"

        current_path = intercept_path if (path_type == "intercepted" or action_type in ["intercept", "tls"]) else direct_path

        nodes_html = f"""
            <circle cx="{victim['x']}" cy="{victim['y']}" r="24" fill="{victim['color']}" filter="url(#glow-green)" />
            <text x="{victim['x']}" y="{victim['y']+4}" text-anchor="middle" font-size="15">{victim['icon']}</text>
            <text x="{victim['x']}" y="{victim['y']+40}" text-anchor="middle" fill="#E2E8F0" font-size="11" font-weight="bold">{victim['label']}</text>

            <circle cx="{attacker['x']}" cy="{attacker['y']}" r="24" fill="{attacker['color']}" filter="url(#glow-red)" />
            <text x="{attacker['x']}" y="{attacker['y']+4}" text-anchor="middle" font-size="15">{attacker['icon']}</text>
            <text x="{attacker['x']}" y="{attacker['y']-32}" text-anchor="middle" fill="#E2E8F0" font-size="11" font-weight="bold">{attacker['label']}</text>

            <circle cx="{router['x']}" cy="{router['y']}" r="24" fill="{router['color']}" filter="url(#glow-blue)" />
            <text x="{router['x']}" y="{router['y']+4}" text-anchor="middle" font-size="15">{router['icon']}</text>
            <text x="{router['x']}" y="{router['y']+38}" text-anchor="middle" fill="#E2E8F0" font-size="11" font-weight="bold">{router['label']}</text>

            <circle cx="{server['x']}" cy="{server['y']}" r="24" fill="{server['color']}" filter="url(#glow-purple)" />
            <text x="{server['x']}" y="{server['y']+4}" text-anchor="middle" font-size="15">{server['icon']}</text>
            <text x="{server['x']}" y="{server['y']+40}" text-anchor="middle" fill="#E2E8F0" font-size="11" font-weight="bold">{server['label']}</text>
        """

    # Action-specific Animation Overlays
    if action_type == "spoof":
        line_color = "#EF4444"
        line_style = "stroke-dasharray: 6; animation: dash 0.8s linear infinite;"
        status_bg = "#450A0A"
        status_border = "#EF4444"
        status_text_color = "#FCA5A5"
        status_msg = "⚡ ARP POISONING EXECUTED: Attacker spoofed MAC address to alter route!"

        if scenario == "s1":
            extra_animation = f"""
                <circle cx="300" cy="45" r="30" fill="none" stroke="#EF4444" stroke-width="2">
                    <animate attributeName="r" values="26;48;26" dur="1.2s" repeatCount="indefinite"/>
                    <animate attributeName="opacity" values="0.9;0.1;0.9" dur="1.2s" repeatCount="indefinite"/>
                </circle>
                <g>
                    <animateMotion path="{spoof_path_1}" dur="1.4s" repeatCount="indefinite" calcMode="linear"/>
                    <circle r="10" fill="#EF4444" filter="url(#glow-red)" />
                    <text font-size="10" text-anchor="middle" dy="3.5" fill="#FFFFFF">⚡</text>
                </g>
                <g>
                    <animateMotion path="{spoof_path_2}" dur="1.4s" repeatCount="indefinite" calcMode="linear"/>
                    <circle r="10" fill="#EF4444" filter="url(#glow-red)" />
                    <text font-size="10" text-anchor="middle" dy="3.5" fill="#FFFFFF">⚡</text>
                </g>
            """
        else:
            extra_animation = f"""
                <circle cx="290" cy="45" r="30" fill="none" stroke="#EF4444" stroke-width="2">
                    <animate attributeName="r" values="24;46;24" dur="1.2s" repeatCount="indefinite"/>
                    <animate attributeName="opacity" values="0.9;0.1;0.9" dur="1.2s" repeatCount="indefinite"/>
                </circle>
                <g>
                    <animateMotion path="{spoof_path_1}" dur="1.4s" repeatCount="indefinite" calcMode="linear"/>
                    <circle r="10" fill="#EF4444" filter="url(#glow-red)" />
                    <text font-size="10" text-anchor="middle" dy="3.5" fill="#FFFFFF">⚡</text>
                </g>
            """

    elif action_type == "restore":
        line_color = "#10B981"
        line_style = "stroke-dasharray: 6; animation: dash 2s linear infinite;"
        status_bg = "#064E3B"
        status_border = "#10B981"
        status_text_color = "#6EE7B7"
        status_msg = "🛡️ CLEAN ARP RESTORED: Authentic network tables & clean direct route restored!"

        extra_animation = f"""
            <circle cx="300" cy="45" r="30" fill="none" stroke="#10B981" stroke-width="2">
                <animate attributeName="r" values="20;40;20" dur="1.5s" repeatCount="2"/>
                <animate attributeName="opacity" values="1;0;1" dur="1.5s" repeatCount="2"/>
            </circle>
        """

    elif action_type == "intercept":
        line_color = "#EF4444"
        line_style = "stroke-dasharray: 6; animation: dash 1.2s linear infinite;"
        status_bg = "#450A0A"
        status_border = "#EF4444"
        status_text_color = "#FCA5A5"
        status_msg = "🚨 MITM INTERCEPTION: Attacker captured, altered payload & forwarded to recipient!"

        extra_animation = f"""
            <g>
                <animateMotion path="{current_path}" dur="2.2s" repeatCount="1" fill="freeze" calcMode="linear"/>
                <circle r="14" fill="#FF4B4B" filter="url(#glow-red)"/>
                <text font-size="11" text-anchor="middle" dy="4" fill="#FFFFFF">⚠️</text>
            </g>
            <g opacity="0">
                <animate attributeName="opacity" values="0;1;0" dur="2.2s" keyTimes="0;0.5;1" repeatCount="1" fill="freeze"/>
                <rect x="220" y="80" width="160" height="22" rx="4" fill="#7F1D1D" stroke="#EF4444" stroke-width="1"/>
                <text x="300" y="95" text-anchor="middle" fill="#FECACA" font-size="9.5" font-weight="bold">⚠️ Payload Altered by MITM!</text>
            </g>
        """

    elif action_type == "tls":
        line_color = "#F59E0B"
        line_style = "stroke-dasharray: 6; animation: dash 1.5s linear infinite;"
        status_bg = "#78350F"
        status_border = "#F59E0B"
        status_text_color = "#FCD34D"
        status_msg = "🔒 SSL/TLS SECURITY ACTIVE: Intercepted by Attacker, but payload remains encrypted!"

        extra_animation = f"""
            <g>
                <animateMotion path="{current_path}" dur="2.2s" repeatCount="1" fill="freeze" calcMode="linear"/>
                <circle r="14" fill="#FFD700" filter="url(#glow-gold)"/>
                <text font-size="11" text-anchor="middle" dy="4" fill="#000000">🔒</text>
            </g>
            <g opacity="0">
                <animate attributeName="opacity" values="0;1;0" dur="2.2s" keyTimes="0;0.5;1" repeatCount="1" fill="freeze"/>
                <rect x="200" y="80" width="200" height="22" rx="4" fill="#1E1B4B" stroke="#818CF8" stroke-width="1"/>
                <text x="300" y="95" text-anchor="middle" fill="#C7D2FE" font-size="9.5" font-weight="bold">🔒 TLS Active (Ciphertext Unreadable)</text>
            </g>
        """

    else:
        line_color = "#10B981"
        line_style = "stroke-dasharray: 6; animation: dash 2s linear infinite;"
        status_bg = "#064E3B"
        status_border = "#10B981"
        status_text_color = "#6EE7B7"
        status_msg = "🟢 CLEAN PACKET TRANSMISSION: Direct authentic communication path."

        pkt_icon = "✉️" if scenario == "s1" else "📧"
        extra_animation = f"""
            <g>
                <animateMotion path="{current_path}" dur="2.0s" repeatCount="1" fill="freeze" calcMode="linear"/>
                <circle r="14" fill="#00F2FE" filter="url(#glow-cyan)"/>
                <text font-size="12" text-anchor="middle" dy="4" fill="#000000">{pkt_icon}</text>
            </g>
        """

    html_code = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                margin: 0;
                background-color: #0d1117;
                font-family: 'Inter', system-ui, sans-serif;
                overflow: hidden;
            }}
            .svg-container {{
                width: 100%;
                height: 295px;
                display: flex;
                justify-content: center;
                align-items: center;
            }}
            .path-line {{
                stroke: {line_color};
                stroke-width: 3.5;
                {line_style}
            }}
            @keyframes dash {{
                to {{ stroke-dashoffset: -100; }}
            }}
        </style>
    </head>
    <body>
        <div class="svg-container">
            <svg width="600" height="290" viewBox="0 0 600 290">
                <defs>
                    <filter id="glow-cyan" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="5" result="blur" />
                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                    <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="6" result="blur" />
                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                    <filter id="glow-green" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="5" result="blur" />
                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                    <filter id="glow-blue" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="5" result="blur" />
                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                    <filter id="glow-gold" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="6" result="blur" />
                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                    <filter id="glow-purple" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="5" result="blur" />
                        <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
                    </filter>
                </defs>

                <path id="path-{trigger_id}" class="path-line" d="{current_path}" fill="none" />
                {nodes_html}
                {extra_animation}

                <rect x="40" y="252" width="520" height="28" rx="6" fill="{status_bg}" stroke="{status_border}" stroke-width="1.5" />
                <text x="300" y="270" text-anchor="middle" fill="{status_text_color}" font-size="11" font-weight="bold">{status_msg}</text>
            </svg>
        </div>
    </body>
    </html>
    """
    components.html(html_code, height=305)


def get_encrypted_hex_blob(payload: str) -> str:
    """Generates an AES-256 ciphertext hex string representation for the UI."""
    h1 = hashlib.sha256(payload.encode("utf-8")).hexdigest().upper()
    h2 = hashlib.md5(payload.encode("utf-8")).hexdigest().upper()
    return f"0x7F4A{h1[:24]} 0x{h1[24:48]} 0x{h2}"


def render_message_encryption_cards(pkt: Optional[Any], scenario_type: str = "computer_mitm"):
    """
    Renders 3 side-by-side inspection cards showing:
    1. Sender Box (Client payload emission)
    2. Network Box (Ciphertext / MITM In-Transit View)
    3. Recipient Box (Decrypted or Tampered payload receipt)
    """
    st.markdown("### 💬 Side-by-Side Message & Encryption Mechanism Inspector")
    col1, col2, col3 = st.columns(3)

    if not pkt or pkt.scenario_type != scenario_type:
        with col1:
            st.info("📤 **1. Sender Box**\n\nAwaiting transmission... Click an action button above.")
        with col2:
            st.info("🔒 **2. Network & Encryption Mechanism**\n\nAwaiting transmission...")
        with col3:
            st.info("📥 **3. Recipient Box**\n\nAwaiting receipt...")
        return

    orig_msg = pkt.original_payload
    final_msg = pkt.payload
    is_enc = pkt.is_encrypted
    is_tam = pkt.is_tampered

    sender_label = "Computer A (Abdullah)" if scenario_type == "computer_mitm" else "Victim (Abdullah)"
    recipient_label = "Computer B (Umer)" if scenario_type == "computer_mitm" else "Mail Server (Umer)"

    # Card 1: Sender Box
    with col1:
        st.markdown(f"""
        <div class="card-box" style="border-left: 4px solid #10B981;">
            <h4 style="color: #10B981; margin-top:0; font-size:1.05rem;">📤 1. Sender Box ({sender_label})</h4>
            <p style="margin-bottom:4px;"><b>Original Message Payload Sent:</b></p>
            <div style="background-color: #0b0e14; padding: 10px; border-radius: 6px; font-family: monospace; color: #34d399; font-size: 0.9rem;">
                {orig_msg}
            </div>
            <p style="margin-top: 10px; font-size: 0.82rem; color: #94a3b8; margin-bottom:0;">
                <b>Encoding:</b> UTF-8 Plaintext<br>
                <b>Status:</b> Emitted by Client Application
            </p>
        </div>
        """, unsafe_allow_html=True)

    # Card 2: Network & Encryption Box
    with col2:
        if is_enc:
            cipher_blob = get_encrypted_hex_blob(orig_msg)
            st.markdown(f"""
            <div class="card-box" style="border-left: 4px solid #F59E0B;">
                <h4 style="color: #F59E0B; margin-top:0; font-size:1.05rem;">🔒 2. Network & TLS Encryption Box</h4>
                <p style="margin-bottom:2px;"><b>Protocol:</b> <code>{pkt.protocol}</code> | <b>Cipher:</b> <code>AES-256-GCM</code></p>
                <p style="margin-bottom:4px;"><b>Key Handshake:</b> RSA-4096 / ECDHE Public Key</p>
                <p style="margin-bottom:4px;"><b>In-Transit Ciphertext (What Attacker Sees):</b></p>
                <div style="background-color: #0b0e14; padding: 10px; border-radius: 6px; font-family: monospace; color: #FCD34D; font-size: 0.85rem; word-break: break-all;">
                    🔒 {cipher_blob}
                </div>
                <p style="margin-top: 8px; font-size: 0.82rem; color: #FBBF24; margin-bottom:0;">
                    <b>Attacker Sniff Result:</b> Intercepted frame payload scrambled into AES-256 ciphertext blob!
                </p>
            </div>
            """, unsafe_allow_html=True)
        elif is_tam:
            st.markdown(f"""
            <div class="card-box" style="border-left: 4px solid #EF4444;">
                <h4 style="color: #EF4444; margin-top:0; font-size:1.05rem;">⚠️ 2. Network Box (MITM Intercepted)</h4>
                <p style="margin-bottom:2px;"><b>Protocol:</b> <code>{pkt.protocol}</code> | <b>Security:</b> 🔓 Plaintext</p>
                <p style="margin-bottom:4px;"><b>Attacker Action:</b> Intercepted raw string & injected payload!</p>
                <p style="margin-bottom:4px;"><b>In-Transit Altered Payload:</b></p>
                <div style="background-color: #0b0e14; padding: 10px; border-radius: 6px; font-family: monospace; color: #FCA5A5; font-size: 0.88rem;">
                    ⚠️ {final_msg}
                </div>
                <p style="margin-top: 8px; font-size: 0.82rem; color: #F87171; margin-bottom:0;">
                    <b>MITM Vulnerability:</b> Plaintext transit allowed arbitrary data tampering.
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="card-box" style="border-left: 4px solid #3B82F6;">
                <h4 style="color: #60A5FA; margin-top:0; font-size:1.05rem;">🌐 2. Network Box (Clean Direct Route)</h4>
                <p style="margin-bottom:2px;"><b>Protocol:</b> <code>{pkt.protocol}</code> | <b>Route:</b> Direct Authentic</p>
                <p style="margin-bottom:4px;"><b>In-Transit Frame Payload:</b></p>
                <div style="background-color: #0b0e14; padding: 10px; border-radius: 6px; font-family: monospace; color: #93C5FD; font-size: 0.88rem;">
                    ✉️ {orig_msg}
                </div>
                <p style="margin-top: 8px; font-size: 0.82rem; color: #93C5FD; margin-bottom:0;">
                    <b>Transit Status:</b> Traversing authentic path cleanly.
                </p>
            </div>
            """, unsafe_allow_html=True)

    # Card 3: Recipient Box
    with col3:
        if is_enc:
            st.markdown(f"""
            <div class="card-box" style="border-left: 4px solid #10B981;">
                <h4 style="color: #10B981; margin-top:0; font-size:1.05rem;">📥 3. Recipient Box ({recipient_label})</h4>
                <p style="margin-bottom:2px;"><b>Decryption Op:</b> <code>D_k(Ciphertext)</code> via Private Key</p>
                <p style="margin-bottom:4px;"><b>Decrypted Payload Received:</b></p>
                <div style="background-color: #0b0e14; padding: 10px; border-radius: 6px; font-family: monospace; color: #34d399; font-size: 0.9rem;">
                    ✅ {orig_msg}
                </div>
                <p style="margin-top: 8px; font-size: 0.82rem; color: #34d399; margin-bottom:0;">
                    <b>TLS Verification:</b> Confidentiality & Integrity verified! Payload secure.
                </p>
            </div>
            """, unsafe_allow_html=True)
        elif is_tam:
            st.markdown(f"""
            <div class="card-box" style="border-left: 4px solid #EF4444;">
                <h4 style="color: #EF4444; margin-top:0; font-size:1.05rem;">📥 3. Recipient Box ({recipient_label})</h4>
                <p style="margin-bottom:2px;"><b>Status:</b> 🚨 Fraudulent Tampered Payload Received!</p>
                <p style="margin-bottom:4px;"><b>Received Payload:</b></p>
                <div style="background-color: #0b0e14; padding: 10px; border-radius: 6px; font-family: monospace; color: #FCA5A5; font-size: 0.88rem;">
                    ⚠️ {final_msg}
                </div>
                <p style="margin-top: 8px; font-size: 0.82rem; color: #F87171; margin-bottom:0;">
                    <b>Attack Impact:</b> Recipient received altered instructions from MITM!
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="card-box" style="border-left: 4px solid #10B981;">
                <h4 style="color: #10B981; margin-top:0; font-size:1.05rem;">📥 3. Recipient Box ({recipient_label})</h4>
                <p style="margin-bottom:2px;"><b>Status:</b> ✅ Authentic Clean Delivery</p>
                <p style="margin-bottom:4px;"><b>Received Payload:</b></p>
                <div style="background-color: #0b0e14; padding: 10px; border-radius: 6px; font-family: monospace; color: #34d399; font-size: 0.9rem;">
                    ✅ {orig_msg}
                </div>
                <p style="margin-top: 8px; font-size: 0.82rem; color: #34d399; margin-bottom:0;">
                    <b>Result:</b> Authentic message received directly from sender.
                </p>
            </div>
            """, unsafe_allow_html=True)


# Application Main Banner
st.markdown("""
<div class="main-banner">
    <h1>🛡️ SilentSnare: MITM Attack Simulation</h1>
    <p>Pure software simulation demonstrating ARP Cache Poisoning, Packet Interception, Payload Alteration, and SSL/TLS Security Protections.</p>
</div>
""", unsafe_allow_html=True)

# Sidebar Options
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

# Navigation Tabs
tab1, tab2, tab_logs = st.tabs([
    "💻 Scenario 1: MITM Between Two Computers",
    "📧 Scenario 2: Email Gateway Hijacking",
    "📜 Session Event Logs & Database"
])

# --- Scenario 1 Tab ---
with tab1:
    st.subheader("Scenario 1: Man-in-the-Middle Between Computer A & Computer B")
    st.caption("Step through the attack lifecycle to see how ARP spoofing redirects traffic through the Attacker.")

    s1_custom_msg = st.text_input(
        "💬 Custom Message to Send from Computer A:",
        value="Hello Umer! Secret Passcode: 9876",
        key="s1_custom_msg_input"
    )

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        if st.button("1️⃣ Normal Direct Packet", use_container_width=True):
            st.session_state.active_packet = sim.s1_normal_communication(
                payload=s1_custom_msg,
                protocol="HTTP"
            )
            st.session_state.last_path_type = "direct"
            st.session_state.last_action = "normal"
            st.session_state.last_scenario = "s1"
            st.session_state.trigger_id = sim.get_trigger_id()
            st.rerun()

    with c2:
        if st.button("2️⃣ Execute ARP Spoofing", use_container_width=True):
            alerts = sim.s1_arp_spoof()
            st.session_state.last_action = "spoof"
            st.session_state.last_scenario = "s1"
            st.session_state.trigger_id = sim.get_trigger_id()
            if alerts:
                st.toast("🚨 IDS Alert: ARP Cache Poisoning Detected!", icon="⚠️")
            st.rerun()

    with c3:
        if st.button("3️⃣ Intercept & Modify Message", use_container_width=True):
            st.session_state.active_packet = sim.s1_intercepted_communication(
                payload=s1_custom_msg,
                protocol="HTTP",
                is_encrypted=False,
                modified_payload=f"Hello Umer! TRANSFER $10,000 to Anonymous Account #666 (Intercepted Original: '{s1_custom_msg}')"
            )
            st.session_state.last_path_type = "intercepted"
            st.session_state.last_action = "intercept"
            st.session_state.last_scenario = "s1"
            st.session_state.trigger_id = sim.get_trigger_id()
            st.rerun()

    with c4:
        if st.button("4️⃣ Send SSL/TLS Encrypted", use_container_width=True):
            st.session_state.active_packet = sim.s1_intercepted_communication(
                payload=s1_custom_msg,
                protocol="HTTPS",
                is_encrypted=True
            )
            st.session_state.last_path_type = "intercepted"
            st.session_state.last_action = "tls"
            st.session_state.last_scenario = "s1"
            st.session_state.trigger_id = sim.get_trigger_id()
            st.rerun()

    with c5:
        if st.button("5️⃣ Restore Clean ARP", use_container_width=True):
            sim.s1_restore_arp()
            st.session_state.last_path_type = "direct"
            st.session_state.last_action = "restore"
            st.session_state.last_scenario = "s1"
            st.session_state.trigger_id = sim.get_trigger_id()
            st.success("Authentic ARP tables restored for Computer A & B!")
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    col_vis, col_pkt = st.columns([3, 2])

    with col_vis:
        st.write("##### 🎞️ Real-Time Packet Path Animation")
        pkt = st.session_state.active_packet
        is_enc = pkt.is_encrypted if pkt else False
        is_tam = pkt.is_tampered if pkt else False
        path_t = st.session_state.last_path_type
        action_t = st.session_state.get("last_action", "normal")
        
        render_animated_packet_diagram(
            scenario="s1",
            path_type=path_t,
            is_encrypted=is_enc,
            is_tampered=is_tam,
            trigger_id=st.session_state.get("trigger_id", sim.trigger_count),
            action_type=action_t
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

    st.markdown("<br>", unsafe_allow_html=True)
    render_message_encryption_cards(pkt, scenario_type="computer_mitm")
    st.divider()

    st.subheader("📋 Active Live ARP Cache Tables")
    col_arp_a, col_arp_b = st.columns(2)

    with col_arp_a:
        st.write("##### Computer A ARP Cache")
        df_arp_a = pd.DataFrame(sim.comp_a.get_arp_comparison())
        st.dataframe(df_arp_a, use_container_width=True, hide_index=True)

    with col_arp_b:
        st.write("##### Computer B ARP Cache")
        df_arp_b = pd.DataFrame(sim.comp_b.get_arp_comparison())
        st.dataframe(df_arp_b, use_container_width=True, hide_index=True)

# --- Scenario 2 Tab ---
with tab2:
    st.subheader("Scenario 2: Email Hijacking via Gateway Spoofing")
    st.caption("Demonstrates how poisoning a victim's Gateway Router ARP entry allows the Attacker to intercept outbound emails.")

    col_s2_sub, col_s2_body = st.columns([1, 2])
    with col_s2_sub:
        s2_custom_sub = st.text_input("📧 Email Subject:", value="Q3 Payroll Draft", key="s2_custom_sub_input")
    with col_s2_body:
        s2_custom_body = st.text_input("📝 Email Body Payload:", value="Please disburse $50,000 team bonus.", key="s2_custom_body_input")

    e1, e2, e3, e4, e5 = st.columns(5)

    with e1:
        if st.button("1️⃣ Normal Email Flow", use_container_width=True):
            st.session_state.active_packet = sim.s2_normal_email(
                subject=s2_custom_sub,
                body=s2_custom_body,
                sender="abdullah@company.com",
                recipient="umer@company.com"
            )
            st.session_state.last_path_type = "direct"
            st.session_state.last_action = "normal"
            st.session_state.last_scenario = "s2"
            st.session_state.trigger_id = sim.get_trigger_id()
            st.rerun()

    with e2:
        if st.button("2️⃣ Spoof Gateway ARP", use_container_width=True):
            alerts = sim.s2_gateway_spoof()
            st.session_state.last_action = "spoof"
            st.session_state.last_scenario = "s2"
            st.session_state.trigger_id = sim.get_trigger_id()
            if alerts:
                st.toast("🚨 IDS Alert: Gateway Impersonation Detected!", icon="⚠️")
            st.rerun()

    with e3:
        if st.button("3️⃣ Intercept & Alter Email", use_container_width=True):
            st.session_state.active_packet = sim.s2_intercepted_email(
                subject=s2_custom_sub,
                body=s2_custom_body,
                sender="abdullah@company.com",
                recipient="umer@company.com",
                protocol="SMTP",
                is_encrypted=False,
                modified_body=f"HIJACKED BY ANONYMOUS: Wire $50,000 funds to offshore account #998877! (Original: '{s2_custom_body}')"
            )
            st.session_state.last_path_type = "intercepted"
            st.session_state.last_action = "intercept"
            st.session_state.last_scenario = "s2"
            st.session_state.trigger_id = sim.get_trigger_id()
            st.rerun()

    with e4:
        if st.button("4️⃣ Send SMTPS Encrypted Email", use_container_width=True):
            st.session_state.active_packet = sim.s2_intercepted_email(
                subject=s2_custom_sub,
                body=s2_custom_body,
                sender="abdullah@company.com",
                recipient="umer@company.com",
                protocol="SMTPS",
                is_encrypted=True
            )
            st.session_state.last_path_type = "intercepted"
            st.session_state.last_action = "tls"
            st.session_state.last_scenario = "s2"
            st.session_state.trigger_id = sim.get_trigger_id()
            st.rerun()

    with e5:
        if st.button("5️⃣ Restore Gateway ARP", use_container_width=True):
            sim.s2_restore_arp()
            st.session_state.last_path_type = "direct"
            st.session_state.last_action = "restore"
            st.session_state.last_scenario = "s2"
            st.session_state.trigger_id = sim.get_trigger_id()
            st.success("Authentic Gateway ARP restored!")
            st.rerun()

    st.markdown("<br>", unsafe_allow_html=True)

    col_e_vis, col_e_pkt = st.columns([3, 2])

    with col_e_vis:
        st.write("##### 🎞️ Email Gateway Routing Animation")
        pkt_e = st.session_state.active_packet
        is_enc_e = pkt_e.is_encrypted if pkt_e else False
        is_tam_e = pkt_e.is_tampered if pkt_e else False
        path_t_e = st.session_state.last_path_type
        action_t_e = st.session_state.get("last_action", "normal")

        render_animated_packet_diagram(
            scenario="s2",
            path_type=path_t_e,
            is_encrypted=is_enc_e,
            is_tampered=is_tam_e,
            trigger_id=st.session_state.get("trigger_id", sim.trigger_count),
            action_type=action_t_e
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

    st.markdown("<br>", unsafe_allow_html=True)
    render_message_encryption_cards(pkt_e, scenario_type="email_gateway")
    st.divider()

    st.subheader("📋 Active Victim ARP Cache Table")
    df_arp_victim = pd.DataFrame(sim.email_victim.get_arp_comparison())
    st.dataframe(df_arp_victim, use_container_width=True, hide_index=True)

# --- Logs Tab ---
with tab_logs:
    st.subheader("📜 Live Event Logs & Security Audit History")

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
