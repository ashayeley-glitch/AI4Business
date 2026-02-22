"""
log_generator.py — Generates simulated cybersecurity log events.

Produces realistic security events including benign activity and
various attack patterns: brute force, port scans, malware, privilege
escalation, data exfiltration, phishing, and DDoS indicators.
"""

import json
import random
import uuid
from datetime import datetime, timedelta
from config import DATA_DIR, RAW_LOGS_PATH


# ── Simulation Pools ─────────────────────────────────────────────

INTERNAL_IPS = [
    "10.0.1.15", "10.0.1.22", "10.0.1.47", "10.0.1.88",
    "10.0.2.10", "10.0.2.33", "192.168.1.100", "192.168.1.205",
]

EXTERNAL_IPS = [
    "185.220.101.34", "45.33.32.156", "91.121.87.10", "103.224.182.250",
    "198.51.100.78", "203.0.113.42", "77.247.181.165", "162.247.74.27",
    "185.56.83.100", "94.102.49.190", "23.129.64.130", "51.15.43.205",
]

USERNAMES = [
    "admin", "root", "jdoe", "econfirm", "sysadmin",
    "deploy_bot", "backup_svc", "m.williams", "a.johnson", "guest",
]

PHISHING_URLS = [
    "http://secure-update-login.xyz/verify",
    "http://account-verify.info/reset",
    "http://company-portal.click/login",
    "http://mail-security-check.top/auth",
    "http://payroll-update.biz/confirm",
]

MALWARE_HASHES = [
    "e99a18c428cb38d5f260853678922e03",
    "d41d8cd98f00b204e9800998ecf8427e",
    "5d41402abc4b2a76b9719d911017c592",
    "098f6bcd4621d373cade4e832627b4f6",
]

PORTS_COMMON = [22, 80, 443, 3306, 5432, 8080, 8443, 3389, 21, 25, 53, 445]


# ── Event Generators ─────────────────────────────────────────────

def _base_event(event_type: str, timestamp: datetime) -> dict:
    return {
        "id": str(uuid.uuid4())[:8],
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
    }


def gen_failed_login(ts: datetime) -> dict:
    evt = _base_event("failed_login", ts)
    evt.update({
        "source_ip": random.choice(EXTERNAL_IPS),
        "target_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(["admin", "root", "administrator", "guest"]),
        "port": 22 if random.random() > 0.5 else 3389,
        "attempts": random.randint(5, 50),
        "message": "Multiple authentication failures detected",
    })
    return evt


def gen_successful_login(ts: datetime) -> dict:
    evt = _base_event("successful_login", ts)
    evt.update({
        "source_ip": random.choice(INTERNAL_IPS),
        "target_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(USERNAMES),
        "port": 22,
        "message": "User authenticated successfully",
    })
    return evt


def gen_port_scan(ts: datetime) -> dict:
    evt = _base_event("port_scan", ts)
    scanned = sorted(random.sample(PORTS_COMMON, k=random.randint(4, 10)))
    evt.update({
        "source_ip": random.choice(EXTERNAL_IPS),
        "target_ip": random.choice(INTERNAL_IPS),
        "ports_scanned": scanned,
        "scan_type": random.choice(["SYN", "TCP_CONNECT", "FIN", "XMAS"]),
        "message": f"Port scan detected: {len(scanned)} ports probed",
    })
    return evt


def gen_malware_signature(ts: datetime) -> dict:
    evt = _base_event("malware_signature", ts)
    evt.update({
        "source_ip": random.choice(INTERNAL_IPS),
        "file_hash": random.choice(MALWARE_HASHES),
        "file_name": random.choice([
            "update.exe", "invoice.pdf.exe", "driver_patch.scr",
            "report_final.docm", "system32_update.bat",
        ]),
        "detection_engine": random.choice(["ClamAV", "YARA", "CrowdStrike", "Defender"]),
        "message": "Malware signature match detected on endpoint",
    })
    return evt


def gen_privilege_escalation(ts: datetime) -> dict:
    evt = _base_event("privilege_escalation", ts)
    evt.update({
        "source_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(USERNAMES),
        "original_role": "user",
        "escalated_role": random.choice(["admin", "root", "SYSTEM"]),
        "method": random.choice([
            "sudo abuse", "token manipulation", "DLL injection",
            "kernel exploit", "group policy modification",
        ]),
        "message": "Unauthorized privilege escalation attempt",
    })
    return evt


def gen_data_exfiltration(ts: datetime) -> dict:
    evt = _base_event("data_exfiltration", ts)
    size_mb = round(random.uniform(50, 2000), 1)
    evt.update({
        "source_ip": random.choice(INTERNAL_IPS),
        "destination_ip": random.choice(EXTERNAL_IPS),
        "data_size_mb": size_mb,
        "protocol": random.choice(["HTTPS", "FTP", "DNS_TUNNEL", "SSH"]),
        "destination_country": random.choice(["RU", "CN", "KP", "IR", "Unknown"]),
        "message": f"Large outbound transfer detected: {size_mb} MB",
    })
    return evt


def gen_phishing_attempt(ts: datetime) -> dict:
    evt = _base_event("phishing_attempt", ts)
    evt.update({
        "source_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(USERNAMES),
        "url": random.choice(PHISHING_URLS),
        "email_subject": random.choice([
            "Urgent: Verify your account",
            "Password reset required",
            "Important payroll update",
            "Action required: Security alert",
        ]),
        "message": "User accessed a known phishing URL",
    })
    return evt


def gen_ddos_indicator(ts: datetime) -> dict:
    evt = _base_event("ddos_indicator", ts)
    rps = random.randint(5000, 50000)
    evt.update({
        "source_ips": random.sample(EXTERNAL_IPS, k=random.randint(3, 6)),
        "target_ip": random.choice(INTERNAL_IPS),
        "requests_per_second": rps,
        "protocol": random.choice(["HTTP", "UDP", "SYN_FLOOD", "DNS_AMPLIFICATION"]),
        "message": f"DDoS pattern detected: ~{rps} req/s from multiple sources",
    })
    return evt


def gen_file_access(ts: datetime) -> dict:
    evt = _base_event("file_access", ts)
    evt.update({
        "source_ip": random.choice(INTERNAL_IPS),
        "username": random.choice(USERNAMES),
        "file_path": random.choice([
            "/var/log/syslog", "/etc/passwd", "/home/user/docs/report.xlsx",
            "C:\\Users\\Public\\Documents\\budget.xlsx",
        ]),
        "action": random.choice(["read", "write", "delete"]),
        "message": "File access event logged",
    })
    return evt


def gen_network_connection(ts: datetime) -> dict:
    evt = _base_event("network_connection", ts)
    evt.update({
        "source_ip": random.choice(INTERNAL_IPS),
        "destination_ip": random.choice(EXTERNAL_IPS + INTERNAL_IPS),
        "port": random.choice(PORTS_COMMON),
        "protocol": random.choice(["TCP", "UDP"]),
        "bytes_sent": random.randint(100, 50000),
        "bytes_received": random.randint(100, 100000),
        "message": "Outbound network connection established",
    })
    return evt


# ── Generator Registry ───────────────────────────────────────────

EVENT_GENERATORS = {
    "failed_login":         (gen_failed_login,         0.12),
    "successful_login":     (gen_successful_login,     0.18),
    "port_scan":            (gen_port_scan,            0.08),
    "malware_signature":    (gen_malware_signature,    0.06),
    "privilege_escalation": (gen_privilege_escalation,  0.05),
    "data_exfiltration":    (gen_data_exfiltration,    0.06),
    "phishing_attempt":     (gen_phishing_attempt,     0.07),
    "ddos_indicator":       (gen_ddos_indicator,       0.04),
    "file_access":          (gen_file_access,          0.16),
    "network_connection":   (gen_network_connection,   0.18),
}


# ── Main Generator Function ─────────────────────────────────────

def generate_logs(num_events: int = 100, hours_back: int = 24) -> list[dict]:
    """
    Generate *num_events* simulated security log entries spread
    over the last *hours_back* hours.
    """
    now = datetime.now()
    types = list(EVENT_GENERATORS.keys())
    weights = [EVENT_GENERATORS[t][1] for t in types]

    logs = []
    for _ in range(num_events):
        offset = timedelta(seconds=random.randint(0, hours_back * 3600))
        ts = now - offset
        event_type = random.choices(types, weights=weights, k=1)[0]
        gen_fn = EVENT_GENERATORS[event_type][0]
        logs.append(gen_fn(ts))

    # Sort by timestamp
    logs.sort(key=lambda e: e["timestamp"])
    return logs


def save_logs(logs: list[dict]) -> str:
    """Write logs to JSON file and return the path."""
    with open(RAW_LOGS_PATH, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, default=str)
    return str(RAW_LOGS_PATH)


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    events = generate_logs(num_events=120, hours_back=48)
    path = save_logs(events)

    # Summary
    from collections import Counter
    counts = Counter(e["event_type"] for e in events)
    print(f"\n✅ Generated {len(events)} log events → {path}\n")
    for etype, count in counts.most_common():
        print(f"   {etype:.<30} {count}")
