"""
dashboard.py — Streamlit dashboard for the Cybersecurity Awareness System.
Aligned with Scope: ChatGPT Analysis, Anomaly Patterns, AI Mitigation, & Ethics.
"""

import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime
import io

# ── Page Config ──────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield — AI Security Hub",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ───────────────────────────────────────────────────
st.markdown("""
<style>
    /* User-Centric Light Theme */
    .stApp { background-color: #f8fafc; color: #0f172a; }
    .block-container { padding-top: 1.5rem; }

    /* KPI metric cards */
    div[data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 12px;
        padding: 18px 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    div[data-testid="stMetric"] label {
        color: #64748b !important;
        font-weight: 500;
    }
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {
        font-size: 1.6rem !important;
        font-weight: 700 !important;
        color: #0f172a !important;
    }

    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background: #ffffff;
        border-right: 1px solid #e2e8f0;
    }

    /* Table styling */
    .stDataFrame { border-radius: 12px; overflow: hidden; border: 1px solid #e2e8f0; }

    /* Headers */
    h1, h2, h3 { letter-spacing: -0.02em; color: #0f172a; }

    /* Custom Alert Boxes */
    .ethics-card {
        padding: 20px;
        background: #eff6ff;
        border-left: 5px solid #2563eb;
        border-radius: 8px;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)


# ── Data Loading & Utils ──────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORT_PATH = DATA_DIR / "threat_report.json"

# Import from config if possible (to keep consistent)
try:
    from config import SEVERITY_COLORS, ETHICS_BRIEF
except ImportError:
    SEVERITY_COLORS = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#d97706", "Low": "#2563eb", "Info": "#475569"}
    ETHICS_BRIEF = {}

CATEGORY_COLORS = {
    "Brute Force": "#1d4ed8", "Reconnaissance": "#0ea5e9", "Malware": "#1e40af",
    "Privilege Escalation": "#3b82f6", "Data Exfiltration": "#60a5fa",
    "Phishing": "#93c5fd", "DDoS": "#2563eb", "Anomalous Traffic": "#94a3b8", "Benign": "#cbd5e1",
}

@st.cache_data(ttl=30)
def load_report():
    if not REPORT_PATH.exists(): return None, None
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        report = json.load(f)
    events = pd.DataFrame(report["events"])
    if "timestamp" in events.columns:
        events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce")
    return report["summary"], events

def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')


# ── Sidebar ──────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=60)
    st.markdown("# CyberShield AI")
    st.markdown("### ChatGPT-Powered Analysis")
    st.divider()

    if st.button("🔄 Run AI Discovery Pipeline", use_container_width=True, type="primary"):
        with st.spinner("Analyzing anomalies..."):
            import sys
            sys.path.insert(0, str(BASE_DIR))
            from pipeline import run_pipeline
            run_pipeline(num_events=120, use_ai=True, verbose=False)
            st.cache_data.clear()
        st.success("Analysis complete!")
        st.rerun()

    st.divider()
    st.markdown("### Project Task Alignment")
    st.info("✓ Log Analysis\n✓ Anomaly Detection\n✓ AI Mitigation\n✓ Ethical Standards")


# ── Main Content ─────────────────────────────────────────────────

st.title("🛡️ Cybersecurity Analysis Dashboard")

summary, events_df = load_report()

if summary is None or events_df is None:
    st.warning("⚠️ No forensic data available. Please run the AI Discovery Pipeline in the sidebar.")
    st.stop()

# Tabs for Deliverables
tab_demo, tab_report, tab_ethics = st.tabs([
    "🔍 Threat Detection Demo", 
    "📊 Forensic Analysis Reports", 
    "⚖️ Security & Ethics Brief"
])

# ── Tab 1: Threat Detection Demo ────────────────────────────────

with tab_demo:
    st.markdown("## AI-Driven Anomaly Detection")
    st.markdown("Visualizing identified attack patterns and ChatGPT-generated mitigations.")

    # KPI Row
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Anomalies Identified", summary["total_threats"])
    col2.metric("Critical Alerts", summary["critical_count"])
    col3.metric("Analysis Confidence", f"{summary['avg_confidence']}%")
    col4.metric("Engine", "ChatGPT (GPT-4o)")

    st.divider()

    # Charts
    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("### ⏱️ Anomalous Pattern Timeline")
        threats_only = events_df[events_df["is_threat"] == True].copy()
        if not threats_only.empty:
            threats_only["hour"] = threats_only["timestamp"].dt.floor("h")
            timeline = threats_only.groupby(["hour", "severity"]).size().reset_index(name="count")
            fig = px.area(timeline, x="hour", y="count", color="severity", color_discrete_map=SEVERITY_COLORS)
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=300, margin=dict(l=0,r=0,t=10,b=0))
            st.plotly_chart(fig, use_container_width=True)
    with c2:
        st.markdown("### 🎯 Pattern Distribution")
        sev_counts = summary.get("severity_counts", {})
        fig_sev = go.Figure(data=[go.Pie(labels=list(sev_counts.keys()), values=list(sev_counts.values()), hole=.5, marker_colors=[SEVERITY_COLORS.get(s, "#6b7280") for s in sev_counts.keys()])])
        fig_sev.update_layout(height=300, margin=dict(l=0,r=0,t=10,b=0), showlegend=False)
        st.plotly_chart(fig_sev, use_container_width=True)

    st.divider()
    st.markdown("### 🩹 AI-Driven Mitigation Strategies")
    
    # Priority Mitigations
    high_priority = events_df[events_df["severity"].isin(["Critical", "High"])].head(5)
    if not high_priority.empty:
        for i, (_, row) in enumerate(high_priority.iterrows()):
            with st.expander(f"⚠️ [{row['severity']}] {row['description'][:80]}...", expanded=(i==0)):
                cols = st.columns([2, 1])
                with cols[0]:
                    st.write(f"**Description:** {row['description']}")
                    st.write(f"**Source:** `{row['source_ip']}`")
                with cols[1]:
                    st.write("**Recommended AI Action:**")
                    for m in row.get("mitigation", []):
                        st.markdown(f"✅ {m}")
    else:
        st.success("No critical anomalies detected in current batch.")


# ── Tab 2: Forensic Analysis Reports ───────────────────────────

with tab_report:
    st.markdown("## Forensic Log Analysis Report")
    st.markdown("Detailed breakdown of all security events for compliance and auditing.")

    # Filter section
    f_sev = st.multiselect("Filter by Severity", options=["Critical", "High", "Medium", "Low", "Info"], default=["Critical", "High", "Medium"])
    
    filtered_df = events_df[events_df["severity"].isin(f_sev)].copy()
    
    # Download Button
    csv = convert_df_to_csv(filtered_df)
    st.download_button(
        label="📥 Download Forensic Report (CSV)",
        data=csv,
        file_name=f'threat_report_{datetime.now().strftime("%Y%m%d")}.csv',
        mime='text/csv',
    )

    st.dataframe(
        filtered_df[["timestamp", "severity", "category", "source_ip", "description", "confidence"]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Event Time"),
            "confidence": st.column_config.ProgressColumn("AI Confidence", format="%d%%", min_value=0, max_value=100)
        }
    )


# ── Tab 3: Security & Ethics Brief ─────────────────────────────

with tab_ethics:
    st.markdown(f"## {ETHICS_BRIEF.get('title', 'Security & Ethics Brief')}")
    
    st.markdown("""
    This project is designed with a strong focus on aligning AI-driven cybersecurity with legal and ethical mandates.
    """)

    col_e1, col_e2 = st.columns(2)
    
    with col_e1:
        st.markdown("### ⚖️ Legal Alignment")
        st.markdown(f"**GDPR & Privacy:** {ETHICS_BRIEF.get('gdpr_compliance', 'N/A')}")
        st.markdown(f"**Compliance Standards:** {ETHICS_BRIEF.get('legal_alignment', 'N/A')}")
        
    with col_e2:
        st.markdown("### 🛡️ Ethical AI Framework")
        st.markdown(f"**Human-in-the-loop:** {ETHICS_BRIEF.get('ethical_ai', 'N/A')}")
        st.markdown(f"**Data Integrity:** {ETHICS_BRIEF.get('privacy_standards', 'N/A')}")

    st.divider()
    
    with st.container():
        st.markdown("#### Responsible AI Statement")
        st.info("""
        The CyberShield system treats AI as a decision-support mechanism. Every mitigation suggested by the ChatGPT-powered engine 
        is mapped to industry-standard frameworks (MITRE ATT&CK, NIST) to ensure technical validity and ethical proportionality.
        """)

# ── Footer ───────────────────────────────────────────────────────
st.divider()
st.caption(f"CyberShield Forensic Engine v1.0 | Report Timestamp: {summary.get('report_generated_at', 'N/A')}")
