# AI-Powered Cybersecurity Threat Detection & Awareness Dashboard

## Tech Stack

| Layer            | Technology         | Version  | Role                                              |
|------------------|--------------------|----------|---------------------------------------------------|
| Language         | Python             | 3.14+    | Core programming language                         |
| AI Engine        | OpenAI API (GPT-4o-mini) | 1.14.0+  | Natural-language threat analysis & classification |
| Data Processing  | Pandas             | 2.1.0+   | Structured log parsing, DataFrames, aggregation   |
| Web Framework    | Streamlit          | 1.31.0+  | Interactive dashboard UI and session management   |
| Visualisation    | Plotly             | 5.18.0+  | Interactive charts (area, donut, bar, heatmap, gauge) |
| Config & Secrets | python-dotenv      | 1.0.0+   | Secure `.env`-based API key management            |
| Styling          | Custom CSS + Google Fonts (Inter, Space Grotesk, Material Symbols) | — | Professional indigo-teal theme |
| Standard Library | json, random, uuid, datetime, pathlib, collections | — | Data generation, file I/O, utilities |

---

## Project Structure

```
Ayele/
├── config.py               # Centralised configuration (paths, keys, severity levels, prompts)
├── log_generator.py        # Simulates realistic cybersecurity log events
├── log_parser.py           # Parses raw JSON logs into structured DataFrames
├── ai_engine.py            # AI-powered + rule-based threat analysis
├── threat_classifier.py    # Merges AI results with parsed logs, generates summaries
├── report_generator.py     # Outputs JSON reports and console alerts
├── pipeline.py             # Orchestrates the 5-step analysis pipeline
├── dashboard.py            # Streamlit web dashboard (main UI)
├── requirements.txt        # Python dependencies
├── .env                    # API keys (not committed)
└── data/
    ├── raw_logs.json       # Generated security events
    └── threat_report.json  # Final analysis report
```

---

## High-Level Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         PIPELINE (pipeline.py)                      │
│                                                                     │
│  Step 1          Step 2          Step 3          Step 4    Step 5   │
│  Generate  ───►  Parse     ───►  Analyse   ───►  Classify ───► Report│
│  Logs            Logs            Threats         Threats       Output│
└─────────────────────────────────────────────────────────────────────┘
                                                        │
                                                        ▼
                                                 ┌─────────────┐
                                                 │ dashboard.py │
                                                 │  (Streamlit) │
                                                 └─────────────┘
```

### Step 1 — Generate Simulated Logs (`log_generator.py`)
- Produces 100–120 realistic security events spread over 24–48 hours.
- 10 event types with probability weights (e.g., failed_login 12 %, successful_login 18 %).
- Draws from pools of internal/external IPs, usernames, phishing URLs, malware hashes, and common ports.
- Output: `data/raw_logs.json`

### Step 2 — Parse & Structure (`log_parser.py`)
- Reads the raw JSON and normalises all event types into a uniform Pandas DataFrame (25+ columns).
- Flags suspicious events automatically based on event type.
- Provides a text formatter (`format_events_for_ai`) for feeding events to the AI engine.

### Step 3 — Threat Analysis (`ai_engine.py`)
- **Primary path (AI):** Sends suspicious events to OpenAI GPT-4o-mini with a structured prompt. Returns JSON containing `is_threat`, `severity`, `category`, `confidence`, `description`, and `mitigation` per event.
- **Fallback path (Rule-based):** If no API key is configured or the API call fails, a heuristic engine classifies threats using event-type rules, severity thresholds, and confidence scoring (60–95 %).
- Graceful degradation ensures the dashboard always has results.

### Step 4 — Classify & Summarise (`threat_classifier.py`)
- Merges AI/rule-based analysis results back into the main DataFrame.
- Computes summary statistics: total events, threat count, threat rate, severity breakdown, category breakdown, top source/target IPs, average confidence.
- Attaches mitigation recommendations from `config.py` templates.

### Step 5 — Report Output (`report_generator.py`)
- Writes a full JSON threat report to `data/threat_report.json` (timestamped, includes summary + all events).
- Prints colour-coded console alerts with severity badges and recommended mitigations.

### Dashboard (`dashboard.py`)
- Reads `data/threat_report.json` on load (cached with 30 s TTL).
- **Sidebar:** Run-analysis button, API key input, how-it-works guide.
- **Tab 1 — Threat Detection:**
  - 6 KPI metric cards (Total Events, Threats, Threat Rate, Critical, High, Avg Confidence).
  - 8 interactive Plotly charts: Threat Timeline (area), Severity Breakdown (donut), Attack Categories (horizontal bar), Top Threat Sources (horizontal bar), Threat Heatmap (hour × category), AI Confidence Distribution (histogram), Category × Severity (stacked bar), Detection Rate (gauge).
  - Auto-generated insight banner summarising key findings.
- **Tab 2 — Forensic Report:**
  - Filterable, sortable threat table with severity and category filters.
  - CSV export and browser-based Print Report feature (generates clean HTML in a new window).
- **Tab 3 — Ethics & Compliance:**
  - Ghana Data Protection Act, 2012 (Act 843) alignment.
  - Cybersecurity Act, 2020 (Act 1038) compliance.
  - CSA incident-response guidelines.
  - Ethical AI disclosure (AI as decision-support, human review required).
- Navigation buttons at the bottom of each tab for intuitive page flow.

---

## Threat Detection Model

| Category              | Mapped Event Type       | Example Indicators                      |
|-----------------------|-------------------------|-----------------------------------------|
| Brute Force           | failed_login            | 20+ failed attempts from single IP      |
| Reconnaissance        | port_scan               | Sequential port scanning activity        |
| Malware               | malware_signature       | Known malware hash detected              |
| Privilege Escalation  | privilege_escalation    | Unauthorised sudo/admin access           |
| Data Exfiltration     | data_exfiltration       | Large outbound data transfers            |
| Phishing              | phishing_attempt        | Suspicious URL / social engineering      |
| DDoS                  | ddos_indicator          | High-volume traffic from botnet IPs      |

Severity levels (ordered): **Critical → High → Medium → Low → Info**

---

## How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# (Optional) Set OpenAI API key
echo OPENAI_API_KEY=sk-... > .env

# Run the analysis pipeline (CLI)
python pipeline.py [num_events]

# Launch the dashboard
streamlit run dashboard.py
```

The dashboard is accessible at **http://localhost:8501** (or the next available port).
