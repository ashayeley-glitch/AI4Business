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

# ── Page Config ──────────────────────────────────────────────────
st.set_page_config(
    page_title="AI-Powered Cybersecurity Threat Detection & Awareness",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto",
)

# ── Viewport meta for mobile ──────────────────────────────────────
st.markdown('<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">', unsafe_allow_html=True)

# ── Custom CSS — Indigo-Teal Professional Theme ─────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    /* Viewport for mobile responsiveness */
    @viewport { width: device-width; }
    @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,1,0');

    :root {
        --indigo: #4f46e5;
        --indigo-dark: #4338ca;
        --indigo-light: #eef2ff;
        --indigo-border: #a5b4fc;
        --teal: #0d9488;
        --red: #dc2626;
        --amber: #f59e0b;
        --slate-900: #0f172a;
        --slate-800: #1e293b;
        --slate-700: #334155;
        --slate-500: #64748b;
        --slate-400: #94a3b8;
        --slate-200: #e2e8f0;
        --slate-100: #f1f5f9;
    }

    .stApp {
        background: linear-gradient(135deg, #f0f4f8 0%, #e8eef6 100%) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }
    .block-container {
        padding: 2rem 2.5rem 3rem !important;
        max-width: 1280px !important;
    }

    /* Typography */
    h1 { font-size: 1.75rem !important; font-weight: 700 !important; color: var(--slate-800) !important; letter-spacing: -0.03em !important; }
    h2 { font-size: 1.25rem !important; font-weight: 600 !important; color: var(--slate-800) !important; }
    h3 { font-size: 1rem !important; font-weight: 600 !important; color: var(--slate-700) !important; }
    p, li { color: #475569 !important; }

    /* KPI Cards */
    div[data-testid="stMetric"],
    div[data-testid="stMetricValue"],
    [data-testid="stMetric"] > div {
        background: #ffffff !important;
        border-radius: 10px !important;
    }
    div[data-testid="stMetric"] {
        border: 1px solid var(--slate-200) !important;
        border-top: 3px solid var(--indigo) !important;
        padding: 16px 18px !important;
        transition: all 0.25s ease !important;
    }
    div[data-testid="stMetric"]:hover {
        box-shadow: 0 6px 16px rgba(79, 70, 229, 0.12) !important;
        transform: translateY(-2px) !important;
    }
    div[data-testid="stMetric"] label {
        color: var(--slate-500) !important;
        font-size: 0.75rem !important;
        font-weight: 500 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
    }
    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        font-size: 1.5rem !important;
        font-weight: 700 !important;
        color: var(--slate-800) !important;
    }

    /* Sidebar */
    [data-testid="stSidebar"],
    [data-testid="stSidebar"] > div,
    [data-testid="stSidebar"] > div > div,
    section[data-testid="stSidebar"],
    section[data-testid="stSidebar"] > div {
        background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%) !important;
        border-right: none !important;
    }
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3, [data-testid="stSidebar"] h4,
    [data-testid="stSidebar"] h5, [data-testid="stSidebar"] h6 {
        color: #e2e8f0 !important;
    }
    [data-testid="stSidebar"] p, [data-testid="stSidebar"] span,
    [data-testid="stSidebar"] label, [data-testid="stSidebar"] .stMarkdown p,
    [data-testid="stSidebar"] .stMarkdown span {
        color: var(--slate-400) !important;
    }
    [data-testid="stSidebar"] hr { border-color: var(--slate-700) !important; }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"], [role="tablist"] {
        gap: 0 !important; background: #ffffff !important;
        border: 1px solid var(--slate-200) !important;
        border-radius: 10px !important; padding: 4px !important;
    }
    .stTabs [data-baseweb="tab"], [role="tab"] {
        border-radius: 8px !important; font-size: 0.85rem !important;
        font-weight: 500 !important; padding: 8px 20px !important;
        color: var(--slate-500) !important;
    }
    .stTabs [aria-selected="true"], [role="tab"][aria-selected="true"],
    .stTabs [aria-selected="true"] p, .stTabs [aria-selected="true"] span,
    [role="tab"][aria-selected="true"] p, [role="tab"][aria-selected="true"] span {
        background: linear-gradient(135deg, var(--indigo), var(--indigo-dark)) !important;
        color: #ffffff !important; border-radius: 8px !important;
    }
    .stTabs [data-baseweb="tab-highlight"],
    .stTabs [data-baseweb="tab-border"] { display: none !important; }

    /* Tables */
    .stDataFrame {
        border-radius: 10px !important; overflow: hidden !important;
        border: 1px solid var(--slate-200) !important;
    }

    /* Expanders */
    [data-testid="stExpander"] summary, .streamlit-expanderHeader {
        font-size: 0.875rem !important; font-weight: 500 !important;
        color: var(--slate-700) !important; background: #ffffff !important;
        border: 1px solid var(--slate-200) !important;
        border-radius: 8px !important; padding: 10px 14px !important;
    }

    /* Buttons */
    button[kind="primary"], [data-testid="stSidebar"] button,
    .stButton button[kind="primary"] {
        background: linear-gradient(135deg, var(--indigo), var(--indigo-dark)) !important;
        border: none !important; border-radius: 8px !important;
        font-weight: 500 !important; color: #ffffff !important;
        transition: all 0.2s ease !important;
    }
    button[kind="primary"] p, button[kind="primary"] span,
    [data-testid="stSidebar"] button p, [data-testid="stSidebar"] button span,
    .stButton button[kind="primary"] p, .stButton button[kind="primary"] span {
        color: #ffffff !important;
    }
    button[kind="primary"]:hover, [data-testid="stSidebar"] button:hover {
        box-shadow: 0 4px 14px rgba(79, 70, 229, 0.35) !important;
        transform: translateY(-1px) !important;
    }
    .stDownloadButton button {
        background: #ffffff !important; border: 1px solid var(--indigo-border) !important;
        border-radius: 8px !important; color: var(--indigo) !important; font-weight: 500 !important;
    }
    .stDownloadButton button:hover {
        background: var(--indigo-light) !important; border-color: var(--indigo) !important;
    }

    /* Multiselect pills */
    [data-baseweb="tag"] {
        background: var(--indigo) !important; color: #ffffff !important;
        border-radius: 6px !important;
    }

    /* Dividers */
    hr { border-color: var(--slate-200) !important; margin: 1.5rem 0 !important; }

    /* Insight banner */
    .insight-banner {
        padding: 14px 20px; background: #ffffff; border: 1px solid var(--slate-200);
        border-left: 4px solid var(--indigo); border-radius: 8px;
        margin-bottom: 20px; font-size: 0.9rem; line-height: 1.5; color: #334155;
    }
    .insight-banner strong { color: var(--slate-800); }

    /* Section header with description */
    .section-desc {
        font-size: 0.8rem; color: #94a3b8; margin-top: -4px; margin-bottom: 12px;
    }

    /* Ethics cards */
    .ethics-card {
        padding: 24px 28px; background: #ffffff; border: 1px solid var(--slate-200);
        border-left: 4px solid var(--indigo); border-radius: 10px;
        margin-bottom: 16px; line-height: 1.7; font-size: 0.88rem;
        transition: all 0.25s ease;
    }
    .ethics-card:hover {
        box-shadow: 0 6px 20px rgba(79, 70, 229, 0.1);
        transform: translateY(-2px);
    }
    .ethics-card strong { color: var(--slate-800); }
    .ethics-card-teal {
        padding: 24px 28px; background: #ffffff; border: 1px solid var(--slate-200);
        border-left: 4px solid var(--teal); border-radius: 10px;
        margin-bottom: 16px; line-height: 1.7; font-size: 0.88rem;
        transition: all 0.25s ease;
    }
    .ethics-card-teal:hover {
        box-shadow: 0 6px 20px rgba(13, 148, 136, 0.1);
        transform: translateY(-2px);
    }
    .ethics-card-teal strong { color: var(--slate-800); }
    .ethics-icon {
        display: inline-flex; align-items: center; justify-content: center;
        width: 36px; height: 36px; border-radius: 8px; margin-bottom: 12px;
        font-size: 1.2rem;
    }
    .ethics-icon-indigo { background: linear-gradient(135deg, #eef2ff, #c7d2fe); color: #4f46e5; }
    .ethics-icon-teal { background: linear-gradient(135deg, #f0fdfa, #99f6e4); color: #0d9488; }
    .ethics-icon-amber { background: linear-gradient(135deg, #fffbeb, #fde68a); color: #d97706; }
    .ethics-icon-red { background: linear-gradient(135deg, #fef2f2, #fecaca); color: #dc2626; }
    .ethics-section-title {
        font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
        letter-spacing: 0.06em; color: var(--slate-400); margin-bottom: 6px;
    }
    .ethics-highlight {
        padding: 20px 24px; background: linear-gradient(135deg, #eef2ff, #f0fdfa);
        border: 1px solid #c7d2fe; border-radius: 10px;
        margin-bottom: 16px; line-height: 1.7; font-size: 0.88rem;
        text-align: center;
    }
    .ethics-highlight strong { color: var(--indigo); }

    /* Dashboard title */
    .dash-title {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 4px;
    }
    .dash-title .material-symbols-outlined {
        font-size: 2rem;
        color: #4f46e5;
        background: linear-gradient(135deg, #eef2ff, #c7d2fe);
        padding: 10px;
        border-radius: 12px;
    }
    @keyframes swing {
        0%   { transform: rotate(-20deg); }
        50%  { transform: rotate(20deg); }
        100% { transform: rotate(-20deg); }
    }
    .sidebar-brand {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .sidebar-brand .material-symbols-outlined {
        font-size: 1.6rem;
        color: #4f46e5;
        background: linear-gradient(135deg, #eef2ff, #c7d2fe);
        padding: 8px;
        border-radius: 10px;
        animation: swing 1.5s ease-in-out infinite;
    }
    .dash-title h1 {
        font-family: 'Space Grotesk', 'Inter', sans-serif !important;
        font-size: 1.85rem !important;
        font-weight: 700 !important;
        color: #1e293b !important;
        letter-spacing: -0.03em !important;
        line-height: 1.3 !important;
        margin: 0 !important;
    }

    /* Footer */
    .footer-text {
        font-size: 0.75rem; color: var(--slate-400);
        text-align: center; padding-top: 1rem;
    }

    /* Nav buttons at bottom of tabs */
    .tab-nav-btn {
        display: inline-block;
        padding: 10px 28px;
        background: linear-gradient(135deg, #4f46e5, #4338ca);
        color: #ffffff !important;
        border-radius: 8px;
        font-weight: 500;
        font-size: 0.85rem;
        cursor: pointer;
        text-decoration: none;
        transition: all 0.2s ease;
        border: none;
    }
    .tab-nav-btn:hover {
        box-shadow: 0 4px 14px rgba(79, 70, 229, 0.35);
        transform: translateY(-1px);
    }
    .tab-nav-btn-outline {
        display: inline-block;
        padding: 10px 28px;
        background: #ffffff;
        color: #4f46e5 !important;
        border: 1px solid #a5b4fc;
        border-radius: 8px;
        font-weight: 500;
        font-size: 0.85rem;
        cursor: pointer;
        text-decoration: none;
        transition: all 0.2s ease;
    }
    .tab-nav-btn-outline:hover {
        background: #eef2ff;
        border-color: #4f46e5;
    }
    .tab-nav-row {
        display: flex;
        justify-content: flex-end;
        gap: 12px;
        margin-top: 20px;
        padding-top: 16px;
    }

    /* ── Mobile-First Responsive ──────────────────────────── */

    /* Small screens (phones, < 640px) */
    @media (max-width: 640px) {
        .block-container {
            padding: 1rem 0.75rem 2rem !important;
            max-width: 100% !important;
        }
        .dash-title {
            flex-direction: column;
            align-items: flex-start;
            gap: 8px;
        }
        .dash-title h1 {
            font-size: 1.25rem !important;
            line-height: 1.35 !important;
        }
        h1 { font-size: 1.25rem !important; }
        h2 { font-size: 1.05rem !important; }
        h3 { font-size: 0.9rem !important; }

        /* Stack all columns full-width (one chart per row) */
        [data-testid="stHorizontalBlock"] {
            flex-wrap: wrap !important;
            gap: 8px !important;
        }
        [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {
            min-width: 100% !important;
            flex: 1 1 100% !important;
        }
        /* KPI cards: 2 per row */
        [data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] [data-testid="stMetric"]) > [data-testid="stColumn"] {
            min-width: 45% !important;
            flex: 1 1 45% !important;
        }
        div[data-testid="stMetric"] {
            padding: 12px 14px !important;
        }
        div[data-testid="stMetric"] [data-testid="stMetricValue"] {
            font-size: 1.2rem !important;
        }

        /* Tabs */
        .stTabs [data-baseweb="tab-list"], [role="tablist"] {
            flex-wrap: wrap !important;
            gap: 4px !important;
        }
        .stTabs [data-baseweb="tab"], [role="tab"] {
            font-size: 0.75rem !important;
            padding: 6px 12px !important;
            flex: 1 1 auto !important;
            text-align: center !important;
        }

        /* Charts fill width */
        .js-plotly-plot, .plotly {
            width: 100% !important;
        }

        /* Nav buttons stack */
        .tab-nav-row {
            flex-direction: column;
            gap: 8px;
        }
        .tab-nav-btn, .tab-nav-btn-outline {
            width: 100%;
            text-align: center;
            padding: 10px 16px;
        }

        /* Insight banner */
        .insight-banner {
            padding: 10px 14px;
            font-size: 0.82rem;
        }

        /* Ethics cards */
        .ethics-card, .ethics-card-teal {
            padding: 14px 16px;
        }

        /* Tables scroll horizontally */
        .stDataFrame {
            overflow-x: auto !important;
        }

        /* Footer */
        .footer-text { font-size: 0.65rem; }
    }

    /* Medium screens (tablets, 641px – 1024px) */
    @media (min-width: 641px) and (max-width: 1024px) {
        .block-container {
            padding: 1.5rem 1.5rem 2.5rem !important;
            max-width: 100% !important;
        }
        .dash-title h1 {
            font-size: 1.5rem !important;
        }

        /* KPIs: 3 per row */
        [data-testid="stHorizontalBlock"] {
            flex-wrap: wrap !important;
        }
        [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {
            min-width: 30% !important;
            flex: 1 1 30% !important;
        }

        /* Charts: single column on narrow tablets */
        .stTabs [data-baseweb="tab"], [role="tab"] {
            font-size: 0.8rem !important;
            padding: 8px 14px !important;
        }
    }

    /* ── Print ─────────────────────────────────────────────── */
    @media print {
        header, [data-testid="stSidebar"], [data-testid="stHeader"],
        .stTabs button, .print-hide { display: none !important; }
        .stApp { background: white !important; }
        .block-container { padding: 0 !important; }
    }
</style>
""", unsafe_allow_html=True)


def nav_to_tab(tab_index):
    """Inject JS to click a tab by its index (0-based) and scroll to top."""
    st.components.v1.html(f"""
        <script>
            const tabs = window.parent.document.querySelectorAll('[role="tab"]');
            if (tabs.length > {tab_index}) {{
                tabs[{tab_index}].click();
                window.parent.document.querySelector('.block-container').scrollIntoView({{ behavior: 'smooth' }});
            }}
        </script>
    """, height=0)


# ── Data Loading ─────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORT_PATH = DATA_DIR / "threat_report.json"

try:
    import config
    from config import SEVERITY_COLORS, ETHICS_BRIEF
except ImportError:
    import types
    config = types.ModuleType("config")
    config.OPENAI_API_KEY = ""
    SEVERITY_COLORS = {
        "Critical": "#dc2626", "High": "#ea580c",
        "Medium": "#d97706", "Low": "#2563eb", "Info": "#475569",
    }
    ETHICS_BRIEF = {}

CHART_PALETTE = {
    "Critical": "#dc2626", "High": "#f59e0b",
    "Medium": "#6366f1", "Low": "#0d9488", "Info": "#94a3b8",
}

CATEGORY_COLORS = {
    "Brute Force": "#4f46e5", "Reconnaissance": "#6366f1",
    "Malware": "#dc2626", "Privilege Escalation": "#f59e0b",
    "Data Exfiltration": "#0d9488", "Phishing": "#8b5cf6",
    "DDoS": "#ec4899", "Anomalous Traffic": "#94a3b8", "Benign": "#cbd5e1",
}

CHART_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter", color="#475569", size=12),
    margin=dict(l=0, r=0, t=10, b=0),
    xaxis=dict(showgrid=False, title="", linecolor="#e2e8f0"),
    yaxis=dict(showgrid=True, gridcolor="#f1f5f9", title="", zeroline=False),
    legend=dict(
        orientation="h", yanchor="bottom", y=1.02,
        xanchor="right", x=1, font=dict(size=11, color="#64748b"),
    ),
)


@st.cache_data(ttl=30)
def load_report():
    if not REPORT_PATH.exists():
        return None, None
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        report = json.load(f)
    events = pd.DataFrame(report["events"])
    if "is_threat" in events.columns:
        events["is_threat"] = events["is_threat"].astype(bool)
    if "timestamp" in events.columns:
        events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce")
    return report["summary"], events

def convert_df_to_csv(df):
    return df.to_csv(index=False).encode("utf-8")

def generate_insight(summary, threats_df):
    """Generate a plain-English summary of the key findings."""
    total = summary["total_events"]
    threats = summary["total_threats"]
    critical = summary["critical_count"]
    high = summary.get("high_count", 0)
    rate = summary.get("threat_rate", 0)

    # Find top category
    top_cat = "N/A"
    cat_counts = summary.get("category_counts", {})
    if cat_counts:
        top_cat = max(cat_counts, key=cat_counts.get)

    # Find peak hour
    peak_hour = ""
    if not threats_df.empty and "timestamp" in threats_df.columns:
        hour_counts = threats_df["timestamp"].dt.hour.value_counts()
        if not hour_counts.empty:
            ph = hour_counts.idxmax()
            peak_hour = f" Peak activity detected around <strong>{ph}:00</strong>."

    severity_note = ""
    if critical > 0:
        severity_note = f" <strong>{critical} critical</strong> and <strong>{high} high</strong> severity alerts require immediate attention."
    elif high > 0:
        severity_note = f" <strong>{high} high</strong> severity alerts were flagged for review."
    else:
        severity_note = " No critical alerts detected in this scan."

    return (
        f"Scanned <strong>{total}</strong> events and identified "
        f"<strong>{threats}</strong> threats (<strong>{rate}%</strong> threat rate). "
        f"The most common attack pattern is <strong>{top_cat}</strong>."
        f"{severity_note}{peak_hour}"
    )


# ── Sidebar ──────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## Group 7")
    st.caption("AI-Powered Security Analysis")
    st.divider()

    st.markdown("##### Getting Started")
    st.caption("Click below to generate simulated security logs and run AI-powered threat analysis.")

    if st.button("Run Analysis Pipeline", width="stretch", type="primary"):
        with st.spinner("Generating logs and analyzing threats..."):
            import sys
            sys.path.insert(0, str(BASE_DIR))
            from pipeline import run_pipeline
            run_pipeline(num_events=120, use_ai=True, verbose=False)
            st.cache_data.clear()
        st.success("Analysis complete")
        st.rerun()

    st.divider()
    st.markdown("##### API Configuration")
    st.caption("Optional: provide your OpenAI key for GPT-powered analysis. Without it, the rule-based engine is used.")
    api_key_input = st.text_input(
        "OpenAI API Key",
        value=st.session_state.get("custom_api_key", ""),
        type="password",
        placeholder="sk-...",
        label_visibility="collapsed",
    )
    if api_key_input:
        st.session_state["custom_api_key"] = api_key_input
        config.OPENAI_API_KEY = api_key_input

    st.divider()
    st.markdown("##### How It Works")
    st.caption(
        "1. Generate simulated security logs\n\n"
        "2. AI analyzes for anomalies & threats\n\n"
        "3. View results in the dashboard\n\n"
        "4. Export reports for compliance"
    )


# ── Header ───────────────────────────────────────────────────────

st.markdown("""
<div class="dash-title">
    <span class="material-symbols-outlined">shield_lock</span>
    <h1>AI-Powered Cybersecurity Threat Detection &amp; Awareness Dashboard</h1>
</div>
<p style="color:#64748b; margin-top:4px; margin-bottom:24px; font-size:0.9rem;">
    Real-time threat analysis, forensic reporting, and compliance review &mdash; powered by ChatGPT
</p>
""", unsafe_allow_html=True)

summary, events_df = load_report()

if summary is None or events_df is None:
    st.markdown("""
    <div class="insight-banner" style="border-left-color: #f59e0b;">
        <strong>Welcome to Group 7 AI.</strong> No analysis data is available yet.
        Click <strong>"Run Analysis Pipeline"</strong> in the sidebar to generate
        simulated security logs and start the AI-powered threat detection.
    </div>
    """, unsafe_allow_html=True)
    st.stop()


# ── Prepare threat data ─────────────────────────────────────────

threats_only = events_df[events_df["is_threat"] == True].copy()

# ── Key Findings Banner ──────────────────────────────────────────

insight_html = generate_insight(summary, threats_only)
st.markdown(f'<div class="insight-banner">{insight_html}</div>', unsafe_allow_html=True)


# ── Tab Navigation ───────────────────────────────────────────────

tab1, tab2, tab3 = st.tabs([
    "Threat Detection",
    "Forensic Report",
    "Ethics & Compliance",
])


# ══════════════════════════════════════════════════════════════════
# TAB 1: THREAT DETECTION
# ══════════════════════════════════════════════════════════════════
with tab1:

    # ── KPI Row ──
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("Total Events", summary["total_events"],
                help="Total number of log events analyzed in this scan")
    col2.metric("Threats Found", summary["total_threats"],
                help="Events classified as potential security threats")
    col3.metric("Threat Rate", f"{summary['threat_rate']}%",
                help="Percentage of events flagged as threats")
    col4.metric("Critical", summary["critical_count"],
                help="Highest severity — requires immediate response")
    col5.metric("High", summary.get("high_count", 0),
                help="Significant threats that should be investigated promptly")
    col6.metric("Confidence", f"{summary['avg_confidence']}%",
                help="Average AI confidence score across all threat detections")

    st.markdown("")

    # ── Row 1: Timeline + Severity Donut ──
    r1c1, r1c2 = st.columns([5, 2])
    with r1c1:
        st.markdown("### Threat Timeline")
        st.markdown('<div class="section-desc">When threats were detected over the analysis window. Hover for details.</div>', unsafe_allow_html=True)
        if not threats_only.empty:
            threats_only["hour"] = threats_only["timestamp"].dt.floor("h")
            timeline = threats_only.groupby(["hour", "severity"]).size().reset_index(name="count")
            fig_timeline = px.area(
                timeline, x="hour", y="count", color="severity",
                color_discrete_map=CHART_PALETTE,
            )
            fig_timeline.update_layout(**CHART_LAYOUT, height=300)
            st.plotly_chart(fig_timeline, width="stretch")
        else:
            st.caption("No threat events to display.")

    with r1c2:
        st.markdown("### Severity Breakdown")
        st.markdown('<div class="section-desc">Proportion of threats by severity level.</div>', unsafe_allow_html=True)
        sev_counts = summary.get("severity_counts", {})
        if sev_counts:
            fig_sev = go.Figure(data=[go.Pie(
                labels=list(sev_counts.keys()),
                values=list(sev_counts.values()),
                hole=0.65,
                marker_colors=[CHART_PALETTE.get(s, "#cbd5e1") for s in sev_counts],
                textinfo="label+percent",
                textfont=dict(size=11, color="#475569"),
                hoverinfo="label+value+percent",
            )])
            fig_sev.update_layout(
                height=300, showlegend=False,
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter"),
                margin=dict(l=0, r=0, t=10, b=0),
            )
            st.plotly_chart(fig_sev, width="stretch")

    st.divider()

    # ── Row 2: Attack Categories + Top Source IPs ──
    r2c1, r2c2 = st.columns(2)
    with r2c1:
        st.markdown("### Attack Categories")
        st.markdown('<div class="section-desc">Types of attack patterns detected, ranked by frequency.</div>', unsafe_allow_html=True)
        if not threats_only.empty:
            cat_counts = threats_only["category"].value_counts().reset_index()
            cat_counts.columns = ["category", "count"]
            cat_counts = cat_counts.sort_values("count", ascending=True)
            fig_cat = px.bar(
                cat_counts, y="category", x="count", orientation="h",
                color="category", color_discrete_map=CATEGORY_COLORS,
            )
            fig_cat.update_layout(**CHART_LAYOUT, height=300, showlegend=False)
            fig_cat.update_traces(texttemplate="%{x}", textposition="outside")
            st.plotly_chart(fig_cat, width="stretch")

    with r2c2:
        st.markdown("### Top Threat Sources")
        st.markdown('<div class="section-desc">IP addresses generating the most threat events.</div>', unsafe_allow_html=True)
        top_sources = summary.get("top_sources", {})
        if top_sources:
            src_df = pd.DataFrame(list(top_sources.items()), columns=["ip", "count"])
            src_df = src_df.sort_values("count", ascending=True).tail(8)
            fig_src = px.bar(
                src_df, y="ip", x="count", orientation="h",
                color_discrete_sequence=["#6366f1"],
            )
            fig_src.update_layout(**CHART_LAYOUT, height=300, showlegend=False)
            fig_src.update_traces(texttemplate="%{x}", textposition="outside")
            st.plotly_chart(fig_src, width="stretch")

    st.divider()

    # ── Row 3: Heatmap + Confidence Distribution ──
    r3c1, r3c2 = st.columns(2)
    with r3c1:
        st.markdown("### Threat Heatmap")
        st.markdown('<div class="section-desc">Attack density by category and hour of day. Darker = more events.</div>', unsafe_allow_html=True)
        if not threats_only.empty and "timestamp" in threats_only.columns:
            threats_only["hour_of_day"] = threats_only["timestamp"].dt.hour
            heat_data = threats_only.groupby(["category", "hour_of_day"]).size().reset_index(name="count")
            heat_pivot = heat_data.pivot(index="category", columns="hour_of_day", values="count").fillna(0)
            fig_heat = go.Figure(data=go.Heatmap(
                z=heat_pivot.values,
                x=[f"{h}:00" for h in heat_pivot.columns],
                y=heat_pivot.index,
                colorscale=[[0, "#eef2ff"], [0.5, "#818cf8"], [1, "#3730a3"]],
                hoverongaps=False,
                showscale=True,
                colorbar=dict(thickness=12, len=0.8),
            ))
            fig_heat.update_layout(
                height=300,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color="#475569", size=11),
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis=dict(title="", side="bottom"),
                yaxis=dict(title=""),
            )
            st.plotly_chart(fig_heat, width="stretch")

    with r3c2:
        st.markdown("### AI Confidence Distribution")
        st.markdown('<div class="section-desc">How confident the AI engine is in each threat classification.</div>', unsafe_allow_html=True)
        if not threats_only.empty and "confidence" in threats_only.columns:
            fig_conf = px.histogram(
                threats_only, x="confidence", nbins=15,
                color_discrete_sequence=["#6366f1"],
                opacity=0.85,
            )
            conf_layout = {**CHART_LAYOUT, "height": 300, "showlegend": False}
            conf_layout["xaxis"] = dict(title="Confidence %", showgrid=False, linecolor="#e2e8f0")
            conf_layout["yaxis"] = dict(title="Count", showgrid=True, gridcolor="#f1f5f9", zeroline=False)
            fig_conf.update_layout(**conf_layout)
            st.plotly_chart(fig_conf, width="stretch")

    st.divider()

    # ── Row 4: Category x Severity + Gauge ──
    r4c1, r4c2 = st.columns([3, 2])
    with r4c1:
        st.markdown("### Category by Severity")
        st.markdown('<div class="section-desc">Severity mix within each attack type. Stacked to show composition.</div>', unsafe_allow_html=True)
        if not threats_only.empty:
            cat_sev = threats_only.groupby(["category", "severity"]).size().reset_index(name="count")
            fig_stack = px.bar(
                cat_sev, x="category", y="count", color="severity",
                color_discrete_map=CHART_PALETTE,
                barmode="stack",
            )
            fig_stack.update_layout(**CHART_LAYOUT, height=300)
            st.plotly_chart(fig_stack, width="stretch")

    with r4c2:
        st.markdown("### Threat Detection Rate")
        st.markdown('<div class="section-desc">Overall percentage of events identified as threats. Red line = 70% alert threshold.</div>', unsafe_allow_html=True)
        threat_rate = summary.get("threat_rate", 0)
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=float(threat_rate),
            number=dict(suffix="%", font=dict(size=36, color="#1e293b")),
            delta=dict(reference=30, suffix="%"),
            gauge=dict(
                axis=dict(range=[0, 100], tickcolor="#cbd5e1"),
                bar=dict(color="#4f46e5"),
                bgcolor="#f1f5f9",
                borderwidth=0,
                steps=[
                    dict(range=[0, 25], color="#eef2ff"),
                    dict(range=[25, 50], color="#c7d2fe"),
                    dict(range=[50, 75], color="#a5b4fc"),
                    dict(range=[75, 100], color="#818cf8"),
                ],
                threshold=dict(line=dict(color="#dc2626", width=3), thickness=0.8, value=70),
            ),
        ))
        fig_gauge.update_layout(
            height=280,
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter", color="#475569"),
            margin=dict(l=30, r=30, t=30, b=10),
        )
        st.plotly_chart(fig_gauge, width="stretch")

    st.divider()

    # ── Mitigation Strategies ──
    st.markdown("### Recommended Mitigations")
    st.markdown('<div class="section-desc">AI-generated response actions for the highest-priority threats. Click to expand.</div>', unsafe_allow_html=True)

    high_priority = events_df[events_df["severity"].isin(["Critical", "High"])].head(5)
    if not high_priority.empty:
        for i, (_, row) in enumerate(high_priority.iterrows()):
            sev = row["severity"]
            icon = "🔴" if sev == "Critical" else "🟠"
            with st.expander(f"{icon} **{sev}** — {row['description'][:90]}", expanded=(i == 0)):
                left, right = st.columns([3, 2])
                with left:
                    st.markdown(f"**Source IP:** `{row['source_ip']}`")
                    if "target_ip" in row and row["target_ip"]:
                        st.markdown(f"**Target IP:** `{row['target_ip']}`")
                    st.markdown(f"**Category:** {row.get('category', 'N/A')}")
                    st.markdown(f"**Confidence:** {row.get('confidence', 'N/A')}%")
                    st.markdown(f"**Description:** {row['description']}")
                with right:
                    st.markdown("**Recommended Actions:**")
                    for m in row.get("mitigation", []):
                        st.markdown(f"- {m}")
    else:
        st.success("No critical or high-severity threats detected in this scan.")

    # ── Navigation to next tab ──
    st.divider()
    nav_col1, nav_col2 = st.columns([4, 1])
    with nav_col1:
        st.caption("Next: View the full forensic event log with filters and CSV export.")
    with nav_col2:
        if st.button("Forensic Report →", width="stretch", type="primary", key="nav_tab1_next"):
            nav_to_tab(1)


# ══════════════════════════════════════════════════════════════════
# TAB 2: FORENSIC REPORT
# ══════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### Event Log")
    st.markdown('<div class="section-desc">Browse, filter, and export all security events. Use the severity filter to focus on what matters.</div>', unsafe_allow_html=True)

    # Filters row
    f_col1, f_col2, f_col3, f_col4 = st.columns([3, 1, 1, 1])
    with f_col1:
        f_sev = st.multiselect(
            "Filter by severity level",
            options=["Critical", "High", "Medium", "Low", "Info"],
            default=["Critical", "High", "Medium"],
            help="Select one or more severity levels to filter the event log",
        )
    with f_col2:
        f_threat_only = st.toggle("Threats only", value=True,
                                   help="Toggle to show only threat events or all events")
    with f_col3:
        filtered_for_export = events_df[events_df["severity"].isin(f_sev)] if f_sev else events_df
        if f_threat_only:
            filtered_for_export = filtered_for_export[filtered_for_export["is_threat"] == True]
        csv_data = convert_df_to_csv(filtered_for_export)
        st.download_button(
            label="Export CSV",
            data=csv_data,
            file_name=f"threat_report_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            width="stretch",
        )
    with f_col4:
        print_clicked = st.button("Print Report", width="stretch", type="primary",
                                   key="print_report",
                                   help="Opens a print-friendly report in a new window")

    filtered_df = events_df.copy()
    if f_sev:
        filtered_df = filtered_df[filtered_df["severity"].isin(f_sev)]
    if f_threat_only:
        filtered_df = filtered_df[filtered_df["is_threat"] == True]

    # Summary bar
    st.markdown(
        f'<div class="section-desc">Showing <strong style="color:#1e293b">{len(filtered_df)}</strong> '
        f'of {len(events_df)} events</div>',
        unsafe_allow_html=True,
    )

    if filtered_df.empty:
        st.info("No events match the selected filters. Try adjusting the severity levels or disabling the 'Threats only' toggle.")
    else:
        display_cols = ["timestamp", "severity", "category", "source_ip", "description", "confidence"]
        if "target_ip" in filtered_df.columns:
            display_cols.insert(4, "target_ip")

        st.dataframe(
            filtered_df[display_cols],
            width="stretch",
            hide_index=True,
            height=450,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time", help="When the event occurred"),
                "severity": st.column_config.TextColumn("Severity", help="Threat severity level"),
                "category": st.column_config.TextColumn("Category", help="Type of attack pattern"),
                "source_ip": st.column_config.TextColumn("Source IP", help="Origin of the event"),
                "target_ip": st.column_config.TextColumn("Target IP", help="Destination of the event"),
                "description": st.column_config.TextColumn("Description", help="AI-generated event description", width="large"),
                "confidence": st.column_config.ProgressColumn(
                    "Confidence", help="AI confidence in this classification",
                    format="%d%%", min_value=0, max_value=100,
                ),
            },
        )

    # ── Print Report (triggered from filter row) ──
    if print_clicked:
        print_df = filtered_df.copy() if not filtered_df.empty else events_df.copy()
        print_cols = ["timestamp", "severity", "category", "source_ip", "description", "confidence"]
        print_cols = [c for c in print_cols if c in print_df.columns]
        if "timestamp" in print_df.columns:
            print_df["timestamp"] = print_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

        sev_color_map = {
            "Critical": "#dc2626", "High": "#f59e0b",
            "Medium": "#6366f1", "Low": "#0d9488", "Info": "#94a3b8",
        }
        rows_html = ""
        for _, r in print_df[print_cols].iterrows():
            sev = r.get("severity", "")
            badge_color = sev_color_map.get(sev, "#94a3b8")
            cells = ""
            for col in print_cols:
                val = r.get(col, "")
                if col == "severity":
                    cells += f'<td><span style="background:{badge_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;">{val}</span></td>'
                elif col == "confidence":
                    cells += f'<td>{val}%</td>'
                else:
                    cells += f'<td>{val}</td>'
            rows_html += f'<tr>{cells}</tr>'

        col_headers = {
            "timestamp": "Time", "severity": "Severity", "category": "Category",
            "source_ip": "Source IP", "description": "Description", "confidence": "Confidence",
        }
        header_html = "".join(f'<th>{col_headers.get(c, c)}</th>' for c in print_cols)

        report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_shown = len(print_df)
        crit_count = len(print_df[print_df["severity"] == "Critical"]) if "severity" in print_df.columns else 0
        high_count = len(print_df[print_df["severity"] == "High"]) if "severity" in print_df.columns else 0

        print_html = f"""
        <html>
        <head>
            <title>Group 7 Forensic Report</title>
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: 'Inter', sans-serif; color: #1e293b; padding: 40px; background: #fff; }}
                .header {{ border-bottom: 3px solid #4f46e5; padding-bottom: 16px; margin-bottom: 24px; }}
                .header h1 {{ font-size: 1.5rem; color: #1e293b; margin-bottom: 4px; }}
                .header p {{ font-size: 0.85rem; color: #64748b; }}
                .summary {{ display: flex; gap: 24px; margin-bottom: 24px; }}
                .summary-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 20px; flex: 1; }}
                .summary-card .label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 4px; }}
                .summary-card .value {{ font-size: 1.25rem; font-weight: 700; color: #1e293b; }}
                table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
                    th {{ background: #f1f5f9; color: #475569; text-align: left; padding: 10px 12px; font-weight: 600;
                          font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e2e8f0; }}
                    td {{ padding: 8px 12px; border-bottom: 1px solid #f1f5f9; color: #334155; vertical-align: top; }}
                    tr:nth-child(even) {{ background: #fafbfc; }}
                    .footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #e2e8f0;
                               font-size: 0.75rem; color: #94a3b8; text-align: center; }}
                    @media print {{
                        body {{ padding: 20px; }}
                        .no-print {{ display: none; }}
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Group 7 AI — Forensic Report</h1>
                    <p>Generated: {report_time}</p>
                </div>
                <div class="summary">
                    <div class="summary-card">
                        <div class="label">Events Shown</div>
                        <div class="value">{total_shown}</div>
                    </div>
                    <div class="summary-card">
                        <div class="label">Critical Alerts</div>
                        <div class="value" style="color:#dc2626;">{crit_count}</div>
                    </div>
                    <div class="summary-card">
                        <div class="label">High Alerts</div>
                        <div class="value" style="color:#f59e0b;">{high_count}</div>
                    </div>
                    <div class="summary-card">
                        <div class="label">Filters Applied</div>
                        <div class="value" style="font-size:0.85rem;">{', '.join(f_sev) if f_sev else 'All'}</div>
                    </div>
                </div>
                <table>
                    <thead><tr>{header_html}</tr></thead>
                    <tbody>{rows_html}</tbody>
                </table>
                <div class="footer">
                    Group 7 Forensic Engine v1.0 — This report is auto-generated for compliance and auditing purposes.
                </div>
                <script>window.onload = function() {{ window.print(); }}</script>
            </body>
            </html>
        """

        st.components.v1.html(f"""
            <script>
                var win = window.open('', '_blank');
                win.document.write(`{print_html.replace(chr(96), "'")}`);
                win.document.close();
            </script>
        """, height=0)

    # ── Navigation buttons ──
    nav_col1, nav_col2, nav_col3 = st.columns([3, 1, 1])
    with nav_col1:
        st.caption("Next: Review the legal and ethical compliance framework.")
    with nav_col2:
        if st.button("← Threat Detection", width="stretch", key="nav_tab2_prev"):
            nav_to_tab(0)
    with nav_col3:
        if st.button("Ethics & Compliance →", width="stretch", type="primary", key="nav_tab2_next"):
            nav_to_tab(2)


# ══════════════════════════════════════════════════════════════════
# TAB 3: ETHICS & COMPLIANCE
# ══════════════════════════════════════════════════════════════════
with tab3:
    st.markdown(f"### {ETHICS_BRIEF.get('title', 'Security & Ethics Brief')}")
    st.markdown('<div class="section-desc">How AI-Powered Cybersecurity Dashboard aligns with Ghana\'s legal framework, international best practices, and responsible AI principles.</div>', unsafe_allow_html=True)

    # ── Mission statement banner ──
    st.markdown("""
<div class="ethics-highlight">
    <strong>Our Commitment</strong><br>
    AI-Powered Cybersecurity Dashboard is built on the principle that cybersecurity and ethics are inseparable.
    Every automated decision is transparent, every data point is handled with care,
    and every mitigation respects the rights and dignity of the individuals involved.
</div>
    """, unsafe_allow_html=True)

    col_e1, col_e2 = st.columns(2)

    with col_e1:
        st.markdown("""
<div class="ethics-card">
    <div class="ethics-icon ethics-icon-indigo">
        <span class="material-symbols-outlined" style="font-size:1.2rem;">gavel</span>
    </div>
    <div class="ethics-section-title">Data Protection</div>
    <strong>Ghana Data Protection Act, 2012 (Act 843)</strong><br>
    This system is designed in full alignment with Ghana's Data Protection Act.
    All personally identifiable information — including IP addresses, usernames,
    and access patterns — is treated as sensitive data. We implement data minimisation,
    collecting only what is necessary for threat detection, and enforce strict retention
    policies to prevent unnecessary storage of personal identifiers.
</div>
        """, unsafe_allow_html=True)

        st.markdown("""
<div class="ethics-card">
    <div class="ethics-icon ethics-icon-red">
        <span class="material-symbols-outlined" style="font-size:1.2rem;">shield</span>
    </div>
    <div class="ethics-section-title">Cybersecurity Compliance</div>
    <strong>Cybersecurity Act, 2020 (Act 1038)</strong><br>
    AI-Powered Cybersecurity Dashboard operates within the regulatory boundaries set by Ghana's Cybersecurity Act.
    This includes mandatory incident reporting for critical threats, protection of critical
    information infrastructure, and adherence to the Cyber Security Authority (CSA) guidelines
    for automated threat detection and response systems. All alerts generated by this platform
    are structured to support compliance reporting workflows.
</div>
        """, unsafe_allow_html=True)

    with col_e2:
        st.markdown("""
<div class="ethics-card-teal">
    <div class="ethics-icon ethics-icon-teal">
        <span class="material-symbols-outlined" style="font-size:1.2rem;">psychology</span>
    </div>
    <div class="ethics-section-title">Responsible AI</div>
    <strong>Human-in-the-Loop Decision Making</strong><br>
    AI is used strictly as a decision-support tool — never as an autonomous decision-maker.
    Every threat classification, severity rating, and mitigation recommendation generated
    by the ChatGPT-powered engine requires human review before action is taken. This ensures
    accountability, prevents false-positive enforcement, and maintains the professional
    judgement of security analysts at the centre of every response.
</div>
        """, unsafe_allow_html=True)

        st.markdown("""
<div class="ethics-card-teal">
    <div class="ethics-icon ethics-icon-amber">
        <span class="material-symbols-outlined" style="font-size:1.2rem;">verified_user</span>
    </div>
    <div class="ethics-section-title">Data Sovereignty & Privacy</div>
    <strong>Local Data Processing & CSA Standards</strong><br>
    All data processing follows the Cyber Security Authority's incident response guidelines,
    with a commitment to local data sovereignty. Security logs are processed and stored
    within controlled environments. No raw log data is transmitted to external services
    beyond the AI analysis API, and all API communications use encrypted channels.
    Privacy impact assessments guide the design of every new feature.
</div>
        """, unsafe_allow_html=True)

    st.markdown("")

    # ── Frameworks & Standards ──
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        st.markdown("""
<div class="ethics-card" style="text-align:center; border-left-color: var(--indigo);">
    <div class="ethics-icon ethics-icon-indigo" style="margin: 0 auto 12px auto;">
        <span class="material-symbols-outlined" style="font-size:1.2rem;">target</span>
    </div>
    <strong>MITRE ATT&CK</strong><br>
    <span style="font-size:0.82rem; color:#64748b;">
        Threat classifications are mapped to the MITRE ATT&CK framework,
        ensuring industry-standard categorisation of tactics, techniques, and procedures.
    </span>
</div>
        """, unsafe_allow_html=True)
    with col_f2:
        st.markdown("""
<div class="ethics-card" style="text-align:center; border-left-color: var(--teal);">
    <div class="ethics-icon ethics-icon-teal" style="margin: 0 auto 12px auto;">
        <span class="material-symbols-outlined" style="font-size:1.2rem;">checklist</span>
    </div>
    <strong>NIST CSF</strong><br>
    <span style="font-size:0.82rem; color:#64748b;">
        Our pipeline follows the NIST Cybersecurity Framework — Identify, Protect, Detect,
        Respond, and Recover — as the backbone for threat analysis and mitigation.
    </span>
</div>
        """, unsafe_allow_html=True)
    with col_f3:
        st.markdown("""
<div class="ethics-card" style="text-align:center; border-left-color: #f59e0b;">
    <div class="ethics-icon ethics-icon-amber" style="margin: 0 auto 12px auto;">
        <span class="material-symbols-outlined" style="font-size:1.2rem;">diversity_3</span>
    </div>
    <strong>Ethical AI Principles</strong><br>
    <span style="font-size:0.82rem; color:#64748b;">
        Transparency, fairness, and accountability guide every AI-driven recommendation.
        No bias amplification. No opaque decisions. Full auditability.
    </span>
</div>
        """, unsafe_allow_html=True)

    st.markdown("")

    # ── Responsible AI Statement ──
    st.markdown("""
<div class="ethics-highlight">
    <div class="ethics-icon ethics-icon-indigo" style="margin: 0 auto 12px auto;">
        <span class="material-symbols-outlined" style="font-size:1.2rem;">handshake</span>
    </div>
    <strong>Responsible AI Statement</strong><br><br>
    AI-Powered Cybersecurity Dashboard treats AI as a decision-support mechanism — never a replacement for human expertise.
    Every mitigation suggested by the ChatGPT-powered engine is mapped to industry-standard frameworks
    (MITRE ATT&CK, NIST CSF) to ensure technical validity and ethical proportionality.
    We are committed to continuous improvement, regular audits of AI outputs, and transparent
    communication about the capabilities and limitations of automated threat detection.
</div>
    """, unsafe_allow_html=True)

    # ── Navigation back ──
    st.divider()
    nav_col1, nav_col2 = st.columns([4, 1])
    with nav_col1:
        st.caption("Go back to the forensic event log.")
    with nav_col2:
        if st.button("← Forensic Report", width="stretch", key="nav_tab3_prev"):
            nav_to_tab(1)


# ── Footer ───────────────────────────────────────────────────────
st.divider()
st.markdown(
    f'<div class="footer-text">Group 7 v1.0 &middot; '
    f'Report generated {summary.get("report_generated_at", "N/A")}</div>',
    unsafe_allow_html=True,
)

# ── Auto-collapse sidebar on scroll, expand at top ───────────────
st.components.v1.html("""
<script>
(function() {
    const doc = window.parent.document;

    // Find the scrollable container — Streamlit nests it differently across versions
    function getScrollContainer() {
        // Try common Streamlit scroll containers
        const candidates = [
            doc.querySelector('section.main .block-container'),
            doc.querySelector('section.main'),
            doc.querySelector('[data-testid="stAppViewContainer"]'),
            doc.querySelector('[data-testid="stMain"]'),
        ];
        for (const el of candidates) {
            if (el && el.scrollHeight > el.clientHeight) return el;
        }
        // Fallback: walk up from block-container to find the scrollable parent
        let node = doc.querySelector('.block-container');
        while (node && node !== doc.body) {
            if (node.scrollHeight > node.clientHeight &&
                getComputedStyle(node).overflow !== 'visible') return node;
            node = node.parentElement;
        }
        return null;
    }

    // Find and click the sidebar toggle button
    function findCloseBtn() {
        return doc.querySelector('[data-testid="stSidebar"] button[aria-expanded="true"]')
            || doc.querySelector('[data-testid="stSidebarCollapseButton"] button')
            || doc.querySelector('button[aria-label="Close sidebar"]');
    }
    function findOpenBtn() {
        return doc.querySelector('[data-testid="stSidebarCollapsedControl"] button')
            || doc.querySelector('button[aria-label="Open sidebar"]')
            || doc.querySelector('button[aria-expanded="false"]');
    }

    // Use CSS approach as primary method — more reliable than button clicks
    const sidebar = doc.querySelector('[data-testid="stSidebar"]');
    if (!sidebar) return;

    let isCollapsed = false;
    const origTransition = sidebar.style.transition;

    function collapseSidebar() {
        if (isCollapsed) return;
        // Try button first
        const btn = findCloseBtn();
        if (btn) {
            btn.click();
            isCollapsed = true;
            return;
        }
        // CSS fallback — slide sidebar off screen
        sidebar.style.transition = 'margin-left 0.3s ease, opacity 0.3s ease';
        sidebar.style.marginLeft = '-300px';
        sidebar.style.opacity = '0';
        isCollapsed = true;
    }

    function expandSidebar() {
        if (!isCollapsed) return;
        const btn = findOpenBtn();
        if (btn) {
            btn.click();
            isCollapsed = false;
            return;
        }
        // CSS fallback — slide sidebar back
        sidebar.style.transition = 'margin-left 0.3s ease, opacity 0.3s ease';
        sidebar.style.marginLeft = '0px';
        sidebar.style.opacity = '1';
        isCollapsed = false;
    }

    // Attach scroll listener after short delay to let Streamlit finish rendering
    setTimeout(function() {
        const scroller = getScrollContainer();
        if (!scroller) return;

        let ticking = false;
        scroller.addEventListener('scroll', function() {
            if (ticking) return;
            ticking = true;
            requestAnimationFrame(function() {
                const y = scroller.scrollTop;
                if (y > 100) {
                    collapseSidebar();
                } else if (y <= 20) {
                    expandSidebar();
                }
                ticking = false;
            });
        });
    }, 1500);
})();
</script>
""", height=0)
