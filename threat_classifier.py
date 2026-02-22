"""
threat_classifier.py — Classifies and enriches threat analysis results.

Merges AI (or rule-based) analysis with parsed log data to produce
a final enriched threat report.
"""

import pandas as pd
from config import SEVERITY_LEVELS, THREAT_CATEGORIES, MITIGATION_TEMPLATES


def classify_threats(
    parsed_df: pd.DataFrame,
    analysis_results: list[dict],
) -> pd.DataFrame:
    """
    Merge analysis results back into the parsed DataFrame,
    producing a unified threat report.
    """
    # Build a dict keyed by event_index
    analysis_map = {r["event_index"]: r for r in analysis_results}

    records = []
    for _, row in parsed_df.iterrows():
        idx = row["index"]
        analysis = analysis_map.get(idx)

        record = {
            "id":            row["id"],
            "timestamp":     row["timestamp"],
            "event_type":    row["event_type"],
            "source_ip":     row["source_ip"],
            "target_ip":     row["target_ip"],
            "username":      row.get("username", ""),
            "message":       row["message"],
        }

        if analysis and analysis.get("is_threat"):
            record["is_threat"]   = True
            record["severity"]    = analysis.get("severity", "Medium")
            record["category"]    = analysis.get("category", row.get("default_category", "Unknown"))
            record["confidence"]  = analysis.get("confidence", 50)
            record["description"] = analysis.get("description", row["message"])
            record["mitigation"]  = analysis.get("mitigation", [])
        else:
            record["is_threat"]   = False
            record["severity"]    = "Info"
            record["category"]    = "Benign"
            record["confidence"]  = 0
            record["description"] = row["message"]
            record["mitigation"]  = []

        records.append(record)

    result_df = pd.DataFrame(records)

    # Ensure severity is ordered categorically
    result_df["severity"] = pd.Categorical(
        result_df["severity"],
        categories=SEVERITY_LEVELS,
        ordered=True,
    )

    return result_df


def get_threat_summary(df: pd.DataFrame) -> dict:
    """
    Generate summary statistics from a classified threat DataFrame.
    """
    threats = df[df["is_threat"]]

    summary = {
        "total_events":    len(df),
        "total_threats":   len(threats),
        "threat_rate":     round(len(threats) / max(len(df), 1) * 100, 1),

        "severity_counts": threats["severity"].value_counts().to_dict() if len(threats) else {},
        "category_counts": threats["category"].value_counts().to_dict() if len(threats) else {},

        "critical_count":  len(threats[threats["severity"] == "Critical"]),
        "high_count":      len(threats[threats["severity"] == "High"]),
        "medium_count":    len(threats[threats["severity"] == "Medium"]),
        "low_count":       len(threats[threats["severity"] == "Low"]),

        "avg_confidence":  round(threats["confidence"].mean(), 1) if len(threats) else 0,

        "top_sources":     threats["source_ip"].value_counts().head(5).to_dict() if len(threats) else {},
        "top_targets":     threats["target_ip"].value_counts().head(5).to_dict() if len(threats) else {},
    }

    return summary


def get_high_priority_threats(df: pd.DataFrame) -> pd.DataFrame:
    """Return only Critical and High severity threats, sorted worst-first."""
    mask = df["severity"].isin(["Critical", "High"]) & df["is_threat"]
    return df[mask].sort_values("severity").reset_index(drop=True)


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Threat Classifier module loaded.")
    print(f"Severity levels: {SEVERITY_LEVELS}")
    print(f"Threat categories: {list(THREAT_CATEGORIES.values())}")
