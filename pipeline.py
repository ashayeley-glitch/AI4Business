"""
pipeline.py — Orchestrates the full cybersecurity analysis pipeline.

Flow: Generate Logs → Parse → AI Analyse → Classify → Report + Alerts
"""

import sys
import time

# Fix Windows console encoding for emoji/unicode output
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from config import ai_available
from log_generator import generate_logs, save_logs
from log_parser import parse_logs, get_suspicious_events, format_events_for_ai
from ai_engine import analyze_with_ai, rule_based_analysis
from threat_classifier import classify_threats, get_threat_summary
from report_generator import generate_report, print_console_alerts


def run_pipeline(
    num_events: int = 120,
    hours_back: int = 48,
    use_ai: bool = True,
    verbose: bool = True,
) -> tuple:
    """
    Run the full analysis pipeline and return (classified_df, summary).
    """
    t0 = time.time()

    # ── Step 1: Generate Logs ────────────────────────────────
    if verbose:
        print("\n🔧 Step 1/5 — Generating simulated security logs...")
    logs = generate_logs(num_events=num_events, hours_back=hours_back)
    log_path = save_logs(logs)
    if verbose:
        print(f"   ✅ Generated {len(logs)} events → {log_path}")

    # ── Step 2: Parse Logs ───────────────────────────────────
    if verbose:
        print("\n📄 Step 2/5 — Parsing and structuring log data...")
    parsed_df = parse_logs(logs)
    suspicious_df = get_suspicious_events(parsed_df)
    if verbose:
        print(f"   ✅ Parsed {len(parsed_df)} events, {len(suspicious_df)} suspicious")

    # ── Step 3: AI Analysis ──────────────────────────────────
    if verbose:
        print("\n🤖 Step 3/5 — Running threat analysis...")

    analysis_results = []

    if use_ai and ai_available():
        if verbose:
            print("   Using OpenAI API for analysis...")
        events_text = format_events_for_ai(suspicious_df)
        analysis_results = analyze_with_ai(events_text)

    # Fallback to rule-based if AI returned nothing
    if not analysis_results:
        if verbose:
            print("   Using rule-based analysis engine...")
        analysis_results = rule_based_analysis(suspicious_df)

    if verbose:
        print(f"   ✅ Analysed {len(analysis_results)} events")

    # ── Step 4: Classify Threats ─────────────────────────────
    if verbose:
        print("\n⚠️  Step 4/5 — Classifying threats...")
    classified_df = classify_threats(parsed_df, analysis_results)
    summary = get_threat_summary(classified_df)
    if verbose:
        print(f"   ✅ {summary['total_threats']} threats classified "
              f"({summary['critical_count']} critical, {summary['high_count']} high)")

    # ── Step 5: Generate Report ──────────────────────────────
    if verbose:
        print("\n📊 Step 5/5 — Generating report...")
    report_path = generate_report(classified_df, summary)

    elapsed = round(time.time() - t0, 2)
    if verbose:
        print(f"   ✅ Report saved → {report_path}")
        print(f"\n   ⏱️  Pipeline completed in {elapsed}s")

    # Print console alerts
    if verbose:
        print_console_alerts(classified_df, summary)

    return classified_df, summary


# ── CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    num = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    run_pipeline(num_events=num, use_ai=True, verbose=True)
