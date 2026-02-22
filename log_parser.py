"""
log_parser.py — Parses raw JSON security logs into structured Pandas DataFrames.
"""

import json
import pandas as pd
from pathlib import Path
from config import RAW_LOGS_PATH, THREAT_CATEGORIES


def load_raw_logs(path: Path = RAW_LOGS_PATH) -> list[dict]:
    """Load raw log events from the JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_logs(raw_logs: list[dict]) -> pd.DataFrame:
    """
    Convert raw log dicts into a structured DataFrame with
    normalised columns and threat flags.
    """
    records = []
    for i, log in enumerate(raw_logs):
        record = {
            "index":       i,
            "id":          log.get("id", ""),
            "timestamp":   log.get("timestamp", ""),
            "event_type":  log.get("event_type", "unknown"),
            "source_ip":   log.get("source_ip", log.get("source_ips", [""])[0] if isinstance(log.get("source_ips"), list) else ""),
            "target_ip":   log.get("target_ip", log.get("destination_ip", "")),
            "username":    log.get("username", ""),
            "message":     log.get("message", ""),
            "port":        log.get("port", None),
        }

        # Extract event-specific metadata
        etype = record["event_type"]

        if etype == "failed_login":
            record["attempts"] = log.get("attempts", 0)
        elif etype == "port_scan":
            record["ports_scanned"] = len(log.get("ports_scanned", []))
            record["scan_type"] = log.get("scan_type", "")
        elif etype == "malware_signature":
            record["file_hash"] = log.get("file_hash", "")
            record["file_name"] = log.get("file_name", "")
            record["detection_engine"] = log.get("detection_engine", "")
        elif etype == "privilege_escalation":
            record["escalated_role"] = log.get("escalated_role", "")
            record["method"] = log.get("method", "")
        elif etype == "data_exfiltration":
            record["data_size_mb"] = log.get("data_size_mb", 0)
            record["protocol"] = log.get("protocol", "")
            record["destination_country"] = log.get("destination_country", "")
        elif etype == "phishing_attempt":
            record["url"] = log.get("url", "")
            record["email_subject"] = log.get("email_subject", "")
        elif etype == "ddos_indicator":
            record["requests_per_second"] = log.get("requests_per_second", 0)
            record["botnet_sources"] = len(log.get("source_ips", []))
            record["protocol"] = log.get("protocol", "")
        elif etype == "network_connection":
            record["protocol"] = log.get("protocol", "")
            record["bytes_sent"] = log.get("bytes_sent", 0)
            record["bytes_received"] = log.get("bytes_received", 0)
        elif etype == "file_access":
            record["file_path"] = log.get("file_path", "")
            record["action"] = log.get("action", "")

        # Flag whether this event type is considered a potential threat
        record["is_suspicious"] = etype in THREAT_CATEGORIES
        record["default_category"] = THREAT_CATEGORIES.get(etype, "Benign")

        records.append(record)

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


def get_suspicious_events(df: pd.DataFrame) -> pd.DataFrame:
    """Return only the rows flagged as suspicious."""
    return df[df["is_suspicious"]].copy()


def format_events_for_ai(df: pd.DataFrame) -> str:
    """
    Format suspicious events into a text block suitable
    for sending to the AI analysis engine.
    """
    lines = []
    for _, row in df.iterrows():
        parts = [
            f"[{row['index']}] {row['timestamp']} | {row['event_type']}",
            f"  Source: {row['source_ip']} → Target: {row['target_ip']}",
            f"  Message: {row['message']}",
        ]
        # Add relevant details
        if row.get("attempts"):
            parts.append(f"  Failed attempts: {row['attempts']}")
        if row.get("ports_scanned"):
            parts.append(f"  Ports scanned: {row['ports_scanned']} ({row.get('scan_type','')})")
        if row.get("file_hash"):
            parts.append(f"  Malware hash: {row['file_hash']} | File: {row.get('file_name','')}")
        if row.get("escalated_role"):
            parts.append(f"  Escalation: user → {row['escalated_role']} via {row.get('method','')}")
        if row.get("data_size_mb"):
            parts.append(f"  Data: {row['data_size_mb']} MB → {row.get('destination_country','')}")
        if row.get("url"):
            parts.append(f"  Phishing URL: {row['url']}")
        if row.get("requests_per_second"):
            parts.append(f"  DDoS: ~{row['requests_per_second']} req/s from {row.get('botnet_sources',0)} sources")

        lines.append("\n".join(parts))

    return "\n\n".join(lines)


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    raw = load_raw_logs()
    df = parse_logs(raw)
    sus = get_suspicious_events(df)

    print(f"\n📄 Parsed {len(df)} log events")
    print(f"🔍 Suspicious events: {len(sus)}")
    print(f"\nEvent type distribution:")
    print(df["event_type"].value_counts().to_string())
