"""
Module: app.py
Author: IBM SkillsBuild Cyber Security Team / BharatCares Project
Date: October 2026
Purpose: CyberShield AI - Interactive Next-Gen Cyber Threat Monitoring & SOC Incident Response Dashboard.
"""

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import sys

# Ensure local imports work
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
from feature_engineering import CyberFeaturePipeline
from incident_responder import IncidentResponseEngine, MITRE_ATTACK_MAPPING

# Page configuration
st.set_page_config(
    page_title="CyberShield AI | IBM SkillsBuild NIDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Dark CSS
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Outfit:wght@400;600;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }
    .main {
        background: radial-gradient(circle at top left, #0d1117, #07090e);
        color: #e6edf3;
    }
    .metric-card {
        background: rgba(22, 27, 34, 0.7);
        border: 1px solid rgba(56, 139, 253, 0.2);
        backdrop-filter: blur(12px);
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #58a6ff;
    }
    .badge-critical {
        background: #ff005522;
        color: #ff3366;
        border: 1px solid #ff3366;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-high {
        background: #ff770022;
        color: #ff9933;
        border: 1px solid #ff9933;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-medium {
        background: #e3b34122;
        color: #f1e05a;
        border: 1px solid #f1e05a;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .badge-low {
        background: #23863622;
        color: #3fb950;
        border: 1px solid #3fb950;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to load model artifacts safely
@st.cache_resource
def load_security_artifacts():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "models")
    
    pipeline_path = os.path.join(models_dir, "feature_pipeline.joblib")
    model_path = os.path.join(models_dir, "best_nids_model.joblib")
    anomaly_path = os.path.join(models_dir, "anomaly_detector.joblib")
    summary_path = os.path.join(models_dir, "evaluation_summary.joblib")
    
    pipeline = CyberFeaturePipeline.load(pipeline_path)
    model = joblib.load(model_path)
    anomaly_detector = joblib.load(anomaly_path)
    summary = joblib.load(summary_path) if os.path.exists(summary_path) else None
    
    return pipeline, model, anomaly_detector, summary

try:
    pipeline, model, anomaly_detector, summary = load_security_artifacts()
    artifacts_ready = True
except Exception as e:
    artifacts_ready = False
    st.error(f"Error loading model artifacts: {str(e)}")

# Header
st.title("🛡️ CyberShield AI: Network Intrusion Detection System")
st.caption("IBM SkillsBuild Cyber Security 2026 | In Collaboration with BharatCares | SOC Threat Telemetry Platform")

# Sidebar Controls
st.sidebar.image("https://img.icons8.com/isometric/100/security-shield.png", width=70)
st.sidebar.header("🕹️ Threat Simulation Panel")
st.sidebar.markdown("Inject live network flow telemetry or select pre-configured threat scenarios:")

preset = st.sidebar.selectbox(
    "Choose Attack Scenario Preset:",
    [
        "Normal Legitimate Traffic",
        "DoS SYN Flood Attack",
        "Stealthy Port Scan / Recon",
        "SSH Brute Force Attack",
        "Web Application SQL Injection",
        "Botnet C2 Beaconing"
    ]
)

# Preset definitions
if preset == "Normal Legitimate Traffic":
    p_proto, p_serv, p_flag = "tcp", "https", "SF"
    p_dur, p_src_b, p_dst_b = 2.4, 750, 4200
    p_count, p_srv_count, p_serror = 4, 4, 0.0
    p_same_srv, p_diff_srv = 1.0, 0.0
    p_dst_h_count, p_dst_h_srv_count = 120, 115
    p_dst_same_srv, p_dst_serror = 0.95, 0.0
elif preset == "DoS SYN Flood Attack":
    p_proto, p_serv, p_flag = "tcp", "http", "S0"
    p_dur, p_src_b, p_dst_b = 0.01, 40, 0
    p_count, p_srv_count, p_serror = 450, 420, 1.0
    p_same_srv, p_diff_srv = 0.98, 0.02
    p_dst_h_count, p_dst_h_srv_count = 255, 12
    p_dst_same_srv, p_dst_serror = 0.04, 1.0
elif preset == "Stealthy Port Scan / Recon":
    p_proto, p_serv, p_flag = "tcp", "other", "REJ"
    p_dur, p_src_b, p_dst_b = 0.05, 54, 0
    p_count, p_srv_count, p_serror = 280, 2, 0.65
    p_same_srv, p_diff_srv = 0.04, 0.92
    p_dst_h_count, p_dst_h_srv_count = 255, 3
    p_dst_same_srv, p_dst_serror = 0.02, 0.60
elif preset == "SSH Brute Force Attack":
    p_proto, p_serv, p_flag = "tcp", "ssh", "SF"
    p_dur, p_src_b, p_dst_b = 2.8, 850, 500
    p_count, p_srv_count, p_serror = 85, 85, 0.15
    p_same_srv, p_diff_srv = 1.0, 0.0
    p_dst_h_count, p_dst_h_srv_count = 95, 95
    p_dst_same_srv, p_dst_serror = 1.0, 0.15
elif preset == "Web Application SQL Injection":
    p_proto, p_serv, p_flag = "tcp", "http", "SF"
    p_dur, p_src_b, p_dst_b = 1.8, 5200, 1800
    p_count, p_srv_count, p_serror = 14, 14, 0.0
    p_same_srv, p_diff_srv = 1.0, 0.0
    p_dst_h_count, p_dst_h_srv_count = 45, 45
    p_dst_same_srv, p_dst_serror = 1.0, 0.0
else: # Botnet C2
    p_proto, p_serv, p_flag = "tcp", "other", "S0"
    p_dur, p_src_b, p_dst_b = 35.0, 256, 128
    p_count, p_srv_count, p_serror = 22, 12, 0.25
    p_same_srv, p_diff_srv = 0.6, 0.4
    p_dst_h_count, p_dst_h_srv_count = 35, 18
    p_dst_same_srv, p_dst_serror = 0.5, 0.20

# Telemetry Adjustment Sliders
with st.sidebar.expander("⚙️ Manual Telemetry Override", expanded=False):
    proto = st.selectbox("Protocol", ["tcp", "udp", "icmp"], index=["tcp", "udp", "icmp"].index(p_proto))
    serv = st.selectbox("Service", ["http", "https", "ssh", "dns", "ftp", "telnet", "smtp", "other"], index=["http", "https", "ssh", "dns", "ftp", "telnet", "smtp", "other"].index(p_serv) if p_serv in ["http", "https", "ssh", "dns", "ftp", "telnet", "smtp", "other"] else 7)
    flag = st.selectbox("TCP Flag", ["SF", "S0", "REJ", "RSTO", "OTH"], index=["SF", "S0", "REJ", "RSTO", "OTH"].index(p_flag) if p_flag in ["SF", "S0", "REJ", "RSTO", "OTH"] else 0)
    duration = st.slider("Duration (sec)", 0.0, 60.0, float(p_dur), 0.1)
    src_bytes = st.slider("Source Bytes", 0, 10000, int(p_src_b), 50)
    dst_bytes = st.slider("Destination Bytes", 0, 10000, int(p_dst_b), 50)
    count = st.slider("Connection Count", 1, 512, int(p_count))
    srv_count = st.slider("Service Count", 1, 512, int(p_srv_count))
    serror_rate = st.slider("SYN Error Rate", 0.0, 1.0, float(p_serror), 0.01)
    same_srv_rate = st.slider("Same Service Rate", 0.0, 1.0, float(p_same_srv), 0.01)
    diff_srv_rate = st.slider("Diff Service Rate", 0.0, 1.0, float(p_diff_srv), 0.01)
    dst_host_count = st.slider("Dst Host Count", 1, 255, int(p_dst_h_count))
    dst_host_srv_count = st.slider("Dst Host Srv Count", 1, 255, int(p_dst_h_srv_count))
    dst_host_same_srv_rate = st.slider("Dst Host Same Srv Rate", 0.0, 1.0, float(p_dst_same_srv), 0.01)
    dst_host_serror_rate = st.slider("Dst Host Serror Rate", 0.0, 1.0, float(p_dst_serror), 0.01)

# Tab layout
tab1, tab2, tab3 = st.tabs(["🚀 Real-Time Threat Analysis & SOAR", "📊 Model Performance Benchmarks", "📖 MITRE ATT&CK & SOC Playbooks"])

with tab1:
    st.subheader("🔍 Incoming Flow Inspection & ML Classification")

    # Create packet dataframe
    packet_data = {
        "duration": [duration],
        "protocol_type": [proto],
        "service": [serv],
        "flag": [flag],
        "src_bytes": [src_bytes],
        "dst_bytes": [dst_bytes],
        "count": [count],
        "srv_count": [srv_count],
        "serror_rate": [serror_rate],
        "same_srv_rate": [same_srv_rate],
        "diff_srv_rate": [diff_srv_rate],
        "dst_host_count": [dst_host_count],
        "dst_host_srv_count": [dst_host_srv_count],
        "dst_host_same_srv_rate": [dst_host_same_srv_rate],
        "dst_host_serror_rate": [dst_host_serror_rate]
    }
    packet_df = pd.DataFrame(packet_data)

    st.dataframe(packet_df, use_container_width=True)

    if artifacts_ready:
        # Preprocess and classify
        X_flow = pipeline.transform(packet_df)
        pred_idx = model.predict(X_flow)[0]
        pred_label = pipeline.label_encoder.inverse_transform([pred_idx])[0]
        
        # Probabilities
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_flow)[0]
            confidence = float(probs[pred_idx])
        else:
            confidence = 1.0
            
        # Isolation Forest Anomaly Detection
        anomaly_indicator = anomaly_detector.predict(X_flow)[0]
        anomaly_score = float(anomaly_detector.decision_function(X_flow)[0])

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            st.metric("Primary Detection", pred_label)
            st.markdown("</div>", unsafe_allow_html=True)

        with col2:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            st.metric("Model Confidence", f"{confidence * 100:.2f}%")
            st.markdown("</div>", unsafe_allow_html=True)

        with col3:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            threat_status = "MALICIOUS 🚨" if pred_label != "Normal" else "BENIGN ✅"
            st.metric("Traffic Assessment", threat_status)
            st.markdown("</div>", unsafe_allow_html=True)

        with col4:
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            iso_status = "ANOMALY DETECTED" if anomaly_indicator == 1 else "NORMAL BASELINE"
            st.metric("Zero-Day Anomaly Engine", iso_status, f"Score: {anomaly_score:.3f}")
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("---")

        # Incident response SOAR report
        incident = IncidentResponseEngine.generate_incident_report(
            attack_type=pred_label,
            confidence=confidence,
            src_ip="192.168.1.185",
            dst_ip="10.0.0.5"
        )

        st.subheader("⚡ Automated Security Orchestration & Incident Response (SOAR)")

        sev_badge = {
            "CRITICAL": "<span class='badge-critical'>CRITICAL</span>",
            "HIGH": "<span class='badge-high'>HIGH</span>",
            "MEDIUM": "<span class='badge-medium'>MEDIUM</span>",
            "LOW": "<span class='badge-low'>LOW / INFO</span>"
        }.get(incident['severity'], "<span class='badge-medium'>MEDIUM</span>")

        st.markdown(f"""
        **Incident Ticket**: `{incident['incident_id']}` | **Severity**: {sev_badge} | **Timestamp**: `{incident['timestamp']}`
        """, unsafe_allow_html=True)

        col_a, col_b = st.columns([1, 1])

        with col_a:
            st.markdown("### 🎯 MITRE ATT&CK Context")
            st.write(f"**Tactic**: `{incident['mitre_tactic']}`")
            st.write(f"**Technique ID**: `{incident['mitre_technique_id']}`")
            st.write(f"**Technique Name**: `{incident['mitre_technique_name']}`")
            st.write(f"**Recommended Containment**: {incident['recommended_containment']}")

        with col_b:
            st.markdown("### 🔒 Automated Firewall Rule Mitigation")
            st.code(incident['automated_firewall_mitigation'], language="bash")
            st.info("Execute on Edge Gateway / iptables or sync with IBM Security Guardium / QRadar SOAR.")

with tab2:
    st.subheader("📊 Multi-Model Performance Benchmarks")
    if artifacts_ready and summary:
        metrics_df = pd.DataFrame(summary["metrics"]).T
        st.dataframe(metrics_df.style.highlight_max(axis=0, color="#1e3a8a"), use_container_width=True)

        st.markdown("### 🏆 Algorithm Comparison")
        st.bar_chart(metrics_df[["accuracy", "f1_score"]])

        st.markdown("### 🔍 Model Evaluation Matrix")
        st.json(summary["best_model_report"])
    else:
        st.info("Run `model_trainer.py` to populate benchmarks.")

with tab3:
    st.subheader("📖 MITRE ATT&CK Threat Taxonomy & SOC Playbooks")
    playbooks_df = pd.DataFrame.from_dict(MITRE_ATTACK_MAPPING, orient="index")
    st.dataframe(playbooks_df[["tactic", "technique_id", "technique_name", "severity", "recommended_action"]], use_container_width=True)
