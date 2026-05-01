# ThreatScope

> Local-first AI-powered phishing analysis and security alert triage tool.

---

ThreatScope is a local-first security triage assistant that analyzes suspicious emails and security alerts, extracts and defangs indicators of compromise (IOCs), enriches them with real threat intelligence, maps findings to MITRE ATT&CK, and assigns an explainable risk score. It generates a plain-English SOC-style investigation report without sending your data to a cloud AI service.

Built for SOC analysts, security students, and homelab operators who want a practical AI security tool they can run on their own machine.

---

## Screenshots

> Screenshots coming soon.

---

## Features

- **Email Analysis:** Parse raw email text or `.eml` files. Detects sender spoofing, SPF/DKIM/DMARC failures, urgency language, and suspicious attachments
- **Email Header Visualizer:** Shows SPF/DKIM/DMARC pass/fail badges, sender domain mismatch comparison, and routing hop count with plain-English explanation
- **IOC Extraction:** Automatically extracts and defangs IPs, domains, URLs, MD5/SHA1/SHA256 hashes, CVE IDs, and email addresses
- **Threat Intelligence Enrichment:** Real-time lookups via VirusTotal, AbuseIPDB, MalwareBazaar, NVD CVE database, and WHOIS with async rate limiting
- **MITRE ATT&CK Mapping:** 20 technique rules with high/medium/low confidence scoring and plain-English descriptions for every technique
- **Explainable Risk Scoring:** Deterministic 0-100 risk score with a per-signal breakdown showing exactly why each point was added
- **AI Investigation Report:** Local LLM via Ollama generates a structured SOC-style report from the evidence. No data leaves your machine
- **PDF Export:** Branded 2-page PDF report — dark navy cover page with risk score, full findings on page 2. Generated at analysis time and downloadable any time from the Reports page
- **Alert Triage:** Supports SIEM-style log snippets in addition to emails
- **Batch Analysis:** Upload and analyze multiple `.eml` files at once with a color-coded results summary table
- **IOC Lookup:** One-off lookup for any IP, domain, URL, hash, or CVE with plain-English verdicts
- **Dashboard:** Analytics overview showing total analyses, average risk score, risk level distribution chart, and recent analyses list
- **Reports Page:** Search, filter by risk level, sort, delete, download individual reports as Markdown or PDF, and export all reports as a zip file
- **Progress Bars:** Step-by-step progress display during analysis so you always know what the tool is doing
- **Plain-English Output:** Every finding is explained in non-technical language, making it accessible to analysts at any level
- **Offline Mode:** Run without API keys for testing or demos

---

## How It Works

```
Suspicious email or alert
        │
        ▼
Parser extracts structure and fields
        │
        ▼
IOC extractor finds IPs, domains, URLs, hashes, CVEs
        │
        ▼
Threat intel enrichment (VirusTotal, AbuseIPDB, MalwareBazaar, NVD, WHOIS)
        │
        ▼
MITRE ATT&CK technique mapping (20 rules, confidence scored)
        │
        ▼
Deterministic risk scoring engine
        │
        ▼
Local LLM generates SOC-style investigation report
        │
        ▼
Report saved as Markdown and PDF
```

Python handles all evidence collection, IOC extraction, API calls, and scoring. The LLM only handles summarization and report writing. This keeps the tool fast, deterministic, and auditable.

---

## Tech Stack

| Layer | Tool | Purpose |
|---|---|---|
| UI | Streamlit | Web interface served locally |
| Local LLM | Ollama + Llama 3.1 8B | AI report generation, runs fully offline |
| Threat Intel | VirusTotal API | Domain, IP, URL, and hash reputation |
| Threat Intel | AbuseIPDB API | IP abuse confidence scoring |
| Threat Intel | MalwareBazaar API | File hash lookup against known malware |
| Vulnerability DB | NVD API v2 | CVE lookup and CVSS scoring |
| Domain Intel | python-whois | Domain registration age and registrar |
| IOC Extraction | re, tldextract | Regex-based indicator extraction |
| Email Parsing | Python email stdlib | Full `.eml` and raw email parsing |
| HTTP Client | httpx | Async API calls with rate limiting |
| Validation | Pydantic | Structured evidence and report schemas |
| PDF Export | weasyprint | Branded 2-page PDF report generation |
| Data | pandas | Batch analysis results and dashboard charts |

---

## Quick Start

### Prerequisites

- Python 3.9 or higher
- [Ollama](https://ollama.com) installed and running
- Free API keys from [VirusTotal](https://virustotal.com) and [AbuseIPDB](https://abuseipdb.com)

### 1. Clone the repository

```bash
git clone https://github.com/TrystanRuiz/ThreatScope.git
cd ThreatScope
```

### 2. Pull the AI model

```bash
ollama pull llama3.1:8b
```

### 3. Set up the environment

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3a. Enable PDF export (optional)

PDF export requires system-level libraries depending on your OS. Skip this step if you only need Markdown reports.

**macOS:**
```bash
brew install pango
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0
```

**Windows:**
```bash
pip install weasyprint
```

Restart the app after installing. If the libraries are not found, the PDF button will show "PDF export unavailable" and the rest of the app will continue to work normally.

### 4. Configure API keys

```bash
cp .env.example .env
```

Open `.env` and add your API keys:

```env
OLLAMA_MODEL=llama3.1:8b
OLLAMA_BASE_URL=http://localhost:11434

VT_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
NVD_API_KEY=your_nvd_key_here
MB_API_KEY=your_malwarebazaar_key_here
```

### 5. Run ThreatScope

```bash
streamlit run app/ui.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## API Keys

| Service | Required | Free Tier Limits | Sign Up |
|---|---|---|---|
| VirusTotal | Yes | 4 requests/min, 500/day | [virustotal.com](https://virustotal.com) |
| AbuseIPDB | Yes | 1,000 checks/day | [abuseipdb.com](https://abuseipdb.com) |
| MalwareBazaar | No | No hard limit | [bazaar.abuse.ch](https://bazaar.abuse.ch) |
| NVD | No | Faster with key | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |

ThreatScope respects all free tier limits automatically via built-in rate limiting. IOCs are deduplicated before API calls to avoid wasting quota.

---

## Running Without API Keys

Set `OFFLINE_MODE=true` in your `.env` to run ThreatScope without any API keys. All enrichment lookups will be skipped, but parsing, IOC extraction, MITRE mapping, scoring, and LLM report generation will still work.

---

## Project Structure

```
ThreatScope/
├── app/
│   ├── ui.py                   # Streamlit app entry point
│   ├── agents/
│   │   ├── analyst_agent.py    # LLM report generation via Ollama
│   │   ├── mitre_agent.py      # MITRE ATT&CK technique mapping (20 rules)
│   │   └── scoring_agent.py    # Deterministic risk scoring
│   ├── parsers/
│   │   ├── email_parser.py     # .eml and raw email parsing
│   │   ├── header_parser.py    # Email header analysis
│   │   ├── log_parser.py       # SIEM alert and log parsing
│   │   └── ioc_extractor.py    # Regex IOC extraction and defanging
│   ├── enrichers/
│   │   ├── virustotal.py       # VirusTotal API with rate limiting
│   │   ├── abuseipdb.py        # AbuseIPDB IP reputation
│   │   ├── nvd.py              # NVD CVE lookup
│   │   ├── malwarebazaar.py    # MalwareBazaar hash lookup
│   │   └── whois_lookup.py     # Domain age and registrar
│   ├── schemas/
│   │   ├── ioc_schema.py       # IOC data models
│   │   └── report_schema.py    # Report output schema
│   ├── utils/
│   │   ├── config.py           # Environment configuration
│   │   ├── defang.py           # IOC defanging utilities
│   │   ├── rate_limiter.py     # Async API rate limiter
│   │   └── logger.py           # Logging setup
│   └── data/
│       └── sample_emails/      # Sample phishing emails for testing
├── reports/                    # Auto-saved Markdown and PDF reports
├── sample_reports/             # Example reports included in repo
├── screenshots/                # App screenshots
├── requirements.txt
├── .env.example
├── Dockerfile
└── LICENSE
```

---

## Limitations and Responsible Use

- **ThreatScope is a defensive analysis tool.** It is designed to help analysts understand suspicious content, not to generate phishing content, automate attacks, bypass security controls, or assist with any offensive activity.
- **All findings require human review.** Risk scores, MITRE mappings, and LLM-generated reports are investigative aids and not authoritative determinations. Never take action based solely on ThreatScope output without independent verification.
- **The LLM can hallucinate.** The local model is instructed to use only the provided evidence, but it may still produce inaccurate or misleading statements. Always cross-reference findings manually.
- **Threat intelligence is not exhaustive.** A clean result from VirusTotal or AbuseIPDB does not guarantee that an indicator is safe. New threats may not yet be cataloged.
- **Do not submit real sensitive data to external APIs.** If enrichment is enabled, IOC values are sent to third-party services. Do not submit client data, internal IP ranges, or proprietary information without authorization.
- **WHOIS data may be incomplete.** WHOIS records are inconsistent across registrars. Missing registration data should be treated as unknown, not automatically suspicious.
- **Free API tier limits apply.** ThreatScope includes built-in rate limiting and deduplication to respect free tier quotas, but heavy usage may exhaust daily limits.

---

## Sample Data

The `app/data/sample_emails/` directory contains synthetic phishing email samples for testing. These are entirely fictional and safe to use.

Do not test ThreatScope with real employee or customer emails, internal corporate logs, private IP ranges, or any data you do not have authorization to analyze.

---

## License

MIT License. See [LICENSE](LICENSE) for full terms.

Copyright (c) 2026 Trystan Ruiz

---

> ThreatScope is a portfolio and educational project. It is not affiliated with or endorsed by MITRE, VirusTotal, AbuseIPDB, or the National Vulnerability Database.
