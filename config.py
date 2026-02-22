"""
config.py — Centralized configuration for the Cybersecurity Awareness System.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ── Paths ────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

RAW_LOGS_PATH = DATA_DIR / "raw_logs.json"
THREAT_REPORT_PATH = DATA_DIR / "threat_report.json"

# ── Environment ──────────────────────────────────────────────────
load_dotenv(BASE_DIR / ".env")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4o-mini"

def ai_available() -> bool:
    """Check if a valid OpenAI API key is configured."""
    return bool(OPENAI_API_KEY) and OPENAI_API_KEY != "your_openai_api_key_here"

# ── Severity Levels ──────────────────────────────────────────────
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]

SEVERITY_COLORS = {
    "Critical": "#1e3a8a", # Deep Blue
    "High":     "#2563eb", # Royal Blue
    "Medium":   "#60a5fa", # Sky Blue
    "Low":      "#93c5fd", # Soft Blue
    "Info":     "#bfdbfe", # Ice Blue
}

# ── Event Types & Threat Categories ──────────────────────────────
EVENT_TYPES = [
    "failed_login",
    "port_scan",
    "malware_signature",
    "privilege_escalation",
    "data_exfiltration",
    "phishing_attempt",
    "ddos_indicator",
    "successful_login",
    "file_access",
    "network_connection",
]

THREAT_CATEGORIES = {
    "failed_login":         "Brute Force",
    "port_scan":            "Reconnaissance",
    "malware_signature":    "Malware",
    "privilege_escalation": "Privilege Escalation",
    "data_exfiltration":    "Data Exfiltration",
    "phishing_attempt":     "Phishing",
    "ddos_indicator":       "DDoS",
}

# ── Mitigation Templates ────────────────────────────────────────
MITIGATION_TEMPLATES = {
    "Brute Force": [
        "Enforce account lockout after 5 failed attempts",
        "Implement multi-factor authentication (MFA)",
        "Deploy CAPTCHA on login pages",
        "Monitor and rate-limit authentication endpoints",
    ],
    "Reconnaissance": [
        "Configure firewall to block sequential port scans",
        "Enable IDS/IPS rules for scan detection",
        "Restrict unnecessary open ports",
        "Use port-knocking or single-packet authorization",
    ],
    "Malware": [
        "Quarantine the affected endpoint immediately",
        "Run full antivirus/EDR scan on the host",
        "Block the malicious file hash across endpoints",
        "Investigate lateral movement from the compromised host",
    ],
    "Privilege Escalation": [
        "Audit and enforce least-privilege access policies",
        "Review sudo/admin access logs for anomalies",
        "Implement Privileged Access Management (PAM)",
        "Enable real-time alerts for privilege changes",
    ],
    "Data Exfiltration": [
        "Block large outbound data transfers immediately",
        "Investigate the source and destination of the transfer",
        "Implement Data Loss Prevention (DLP) policies",
        "Review and restrict cloud storage access",
    ],
    "Phishing": [
        "Block the reported phishing URL across the network",
        "Send a security awareness alert to all employees",
        "Check if credentials were compromised and force resets",
        "Report the phishing domain to relevant authorities",
    ],
    "DDoS": [
        "Activate DDoS mitigation services (CDN/WAF)",
        "Rate-limit incoming traffic from suspicious sources",
        "Blackhole route traffic from identified botnet IPs",
        "Contact ISP for upstream filtering assistance",
    ],
}

# ── Ethics & Standards Brief ─────────────────────────────────────
ETHICS_BRIEF = {
    "title": "Security, Ethics & Legal Standards Alignment",
    "gdpr_compliance": "System implements data minimization by focusing only on security-relevant fields. IP addresses are treated as sensitive identifiers.",
    "ethical_ai": "AI analysis is used as a decision-support tool, not an autonomous agent. All mitigations require human review before deployment.",
    "legal_alignment": "Analysis remains within the boundaries of corporate security monitoring policies and local data protection laws (e.g., CCPA/GDPR).",
    "privacy_standards": "Raw log data is stored locally. No personally identifiable information (PII) beyond usernames and IPs is processed through AI engines.",
}

# ── AI Prompt ────────────────────────────────────────────────────
AI_ANALYSIS_PROMPT = """You are an expert cybersecurity analyst powered by ChatGPT. 
Analyze the following security log events to identify anomalies and specific attack patterns.

For each suspicious event or anomaly, return a JSON array with objects containing:
- "event_index": the index of the event in the input list
- "is_threat": true/false
- "severity": one of "Critical", "High", "Medium", "Low", "Info"
- "category": the detected pattern (e.g., "Brute Force", "Reconnaissance", "Malware", "Privilege Escalation", "Data Exfiltration", "Phishing", "DDoS", "Anomalous Traffic")
- "confidence": a confidence score 0-100
- "description": a brief description of the anomaly or threat pattern
- "mitigation": a list of 2-3 specific AI-driven recommended actions

Respond ONLY with valid JSON. No markdown, no explanation outside the JSON.

Security Events:
{events}"""
