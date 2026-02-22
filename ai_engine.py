"""
ai_engine.py — AI Analysis Engine using OpenAI API for threat detection.

Falls back to rule-based analysis when the API key is not configured.
"""

import json
from config import (
    OPENAI_API_KEY, OPENAI_MODEL, AI_ANALYSIS_PROMPT,
    ai_available, THREAT_CATEGORIES, MITIGATION_TEMPLATES,
)


def analyze_with_ai(events_text: str) -> list[dict]:
    """
    Send parsed security events to OpenAI for threat analysis.
    Returns a list of threat assessment dicts.
    """
    if not ai_available():
        print("⚠️  OpenAI API key not configured — using rule-based fallback.")
        return []

    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)

        prompt = AI_ANALYSIS_PROMPT.format(events=events_text)

        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are an expert cybersecurity threat analyst. Respond only with valid JSON."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=4000,
        )

        result_text = response.choices[0].message.content.strip()

        # Strip markdown code fences if present
        if result_text.startswith("```"):
            result_text = result_text.split("\n", 1)[1]
            if result_text.endswith("```"):
                result_text = result_text[:-3]
            result_text = result_text.strip()

        return json.loads(result_text)

    except Exception as e:
        print(f"⚠️  AI analysis failed: {e}")
        print("   Falling back to rule-based analysis.")
        return []


def rule_based_analysis(df) -> list[dict]:
    """
    Fallback threat analysis using predefined rules.
    Works without any API key.
    """
    results = []

    for _, row in df.iterrows():
        etype = row["event_type"]
        category = THREAT_CATEGORIES.get(etype)

        if not category:
            continue  # skip benign events

        # Determine severity based on event type and attributes
        severity, confidence, description = _classify_by_rules(row, etype, category)

        mitigation = MITIGATION_TEMPLATES.get(category, [
            "Investigate the event further",
            "Review system logs for related activity",
        ])[:3]

        results.append({
            "event_index": row["index"],
            "is_threat": True,
            "severity": severity,
            "category": category,
            "confidence": confidence,
            "description": description,
            "mitigation": mitigation,
        })

    return results


def _classify_by_rules(row, etype: str, category: str) -> tuple:
    """Return (severity, confidence, description) based on heuristic rules."""

    if etype == "failed_login":
        attempts = row.get("attempts", 0)
        if attempts >= 20:
            return "Critical", 92, f"Brute-force attack: {attempts} failed login attempts from {row['source_ip']}"
        elif attempts >= 10:
            return "High", 85, f"Sustained brute-force: {attempts} failed attempts targeting {row.get('username','unknown')}"
        else:
            return "Medium", 70, f"Multiple failed logins ({attempts}) from external IP {row['source_ip']}"

    elif etype == "port_scan":
        ports = row.get("ports_scanned", 0)
        scan_type = row.get("scan_type", "")
        if ports >= 8 or scan_type in ("FIN", "XMAS"):
            return "High", 88, f"Aggressive {scan_type} port scan: {ports} ports probed from {row['source_ip']}"
        else:
            return "Medium", 75, f"Port reconnaissance: {ports} ports scanned by {row['source_ip']}"

    elif etype == "malware_signature":
        return "Critical", 95, f"Malware detected: {row.get('file_name','')} (hash: {row.get('file_hash','')[:12]}...) by {row.get('detection_engine','')}"

    elif etype == "privilege_escalation":
        escalated = row.get("escalated_role", "")
        if escalated in ("root", "SYSTEM"):
            return "Critical", 93, f"Privilege escalation to {escalated} via {row.get('method','')} by {row.get('username','')}"
        else:
            return "High", 82, f"Privilege escalation attempt: {row.get('username','')} → {escalated}"

    elif etype == "data_exfiltration":
        size = row.get("data_size_mb", 0)
        country = row.get("destination_country", "")
        if size >= 500 or country in ("RU", "CN", "KP", "IR"):
            return "Critical", 90, f"Data exfiltration: {size} MB transferred to {country} via {row.get('protocol','')}"
        else:
            return "High", 78, f"Suspicious outbound transfer: {size} MB to {row.get('target_ip','')}"

    elif etype == "phishing_attempt":
        return "High", 85, f"Phishing: user {row.get('username','')} accessed {row.get('url','suspicious URL')}"

    elif etype == "ddos_indicator":
        rps = row.get("requests_per_second", 0)
        if rps >= 20000:
            return "Critical", 94, f"Major DDoS attack: ~{rps} req/s from {row.get('botnet_sources',0)} sources"
        else:
            return "High", 80, f"DDoS indicator: ~{rps} req/s targeting {row.get('target_ip','')}"

    return "Medium", 60, f"Suspicious {category} activity detected"


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("AI Engine module loaded.")
    print(f"OpenAI API available: {ai_available()}")
    print(f"Model: {OPENAI_MODEL}")
