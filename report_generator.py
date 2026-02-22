"""
report_generator.py — Generates JSON threat reports and console alerts.
"""

import sys
import json
from datetime import datetime

# Fix Windows console encoding for emoji/unicode output
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import pandas as pd
from config import THREAT_REPORT_PATH, SEVERITY_COLORS


def generate_report(classified_df: pd.DataFrame, summary: dict) -> str:
    """
    Write the full threat report to JSON and return the file path.
    """
    threats_list = []
    for _, row in classified_df.iterrows():
        threats_list.append({
            "id":          row["id"],
            "timestamp":   row["timestamp"].isoformat() if pd.notna(row["timestamp"]) else "",
            "event_type":  row["event_type"],
            "source_ip":   row["source_ip"],
            "target_ip":   row["target_ip"],
            "username":    row.get("username", ""),
            "is_threat":   bool(row["is_threat"]),
            "severity":    str(row["severity"]),
            "category":    row["category"],
            "confidence":  int(row.get("confidence", 0)),
            "description": row["description"],
            "mitigation":  row.get("mitigation", []),
        })

    report = {
        "report_generated_at": datetime.now().isoformat(),
        "summary": summary,
        "events": threats_list,
    }

    with open(THREAT_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    return str(THREAT_REPORT_PATH)


def print_console_alerts(classified_df: pd.DataFrame, summary: dict):
    """
    Print colour-coded console output for the threat analysis.
    """
    # ANSI colour codes
    C = {
        "red":     "\033[91m",
        "orange":  "\033[93m",
        "yellow":  "\033[33m",
        "blue":    "\033[94m",
        "green":   "\033[92m",
        "gray":    "\033[90m",
        "bold":    "\033[1m",
        "reset":   "\033[0m",
    }

    sev_color = {
        "Critical": C["red"],
        "High":     C["orange"],
        "Medium":   C["yellow"],
        "Low":      C["blue"],
        "Info":     C["gray"],
    }

    print(f"\n{'='*64}")
    print(f"{C['bold']}  🛡️  CYBERSECURITY THREAT ANALYSIS REPORT{C['reset']}")
    print(f"{'='*64}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*64}")

    # Summary stats
    print(f"\n  📊 {C['bold']}Summary{C['reset']}")
    print(f"     Total Events Analysed ... {summary['total_events']}")
    print(f"     Threats Detected ........ {C['red']}{summary['total_threats']}{C['reset']}")
    print(f"     Threat Rate ............. {summary['threat_rate']}%")
    print(f"     Avg Confidence .......... {summary['avg_confidence']}%")

    print(f"\n  ⚡ {C['bold']}Severity Breakdown{C['reset']}")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = summary.get("severity_counts", {}).get(sev, 0)
        if count:
            print(f"     {sev_color[sev]}● {sev:.<12} {count}{C['reset']}")

    print(f"\n  📂 {C['bold']}Attack Categories{C['reset']}")
    for cat, count in sorted(summary.get("category_counts", {}).items(), key=lambda x: -x[1]):
        print(f"     • {cat:.<24} {count}")

    # Critical & High alerts
    critical_high = classified_df[
        classified_df["severity"].isin(["Critical", "High"]) & classified_df["is_threat"]
    ].sort_values("severity")

    if len(critical_high) > 0:
        print(f"\n  {C['red']}{C['bold']}🚨 HIGH‑PRIORITY ALERTS{C['reset']}")
        print(f"  {'─'*58}")

        for _, row in critical_high.iterrows():
            sc = sev_color.get(str(row["severity"]), C["gray"])
            print(f"\n  {sc}[{row['severity']}]{C['reset']} {row['description']}")
            print(f"    {C['gray']}Source: {row['source_ip']} → Target: {row['target_ip']}{C['reset']}")
            print(f"    {C['gray']}Category: {row['category']} | Confidence: {row.get('confidence',0)}%{C['reset']}")

            mitigations = row.get("mitigation", [])
            if mitigations:
                print(f"    {C['green']}Mitigation:{C['reset']}")
                for m in (mitigations if isinstance(mitigations, list) else [mitigations]):
                    print(f"      → {m}")

    print(f"\n{'='*64}")
    print(f"  Report saved to: {THREAT_REPORT_PATH}")
    print(f"{'='*64}\n")


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Report Generator module loaded.")
