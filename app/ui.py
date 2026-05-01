import asyncio
import sys
from datetime import datetime
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.parsers.email_parser import parse_raw_email
from app.parsers.header_parser import parse_headers
from app.parsers.log_parser import parse_log
from app.enrichers import virustotal, abuseipdb, nvd, whois_lookup, malwarebazaar
from app.agents.scoring_agent import score
from app.agents.mitre_agent import map_techniques
from app.agents.analyst_agent import generate_report
from app.utils.config import config

REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
SAMPLE_PATH = Path(__file__).parent / "data/sample_emails/sample_phishing.eml"

st.set_page_config(page_title="ThreatScope", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
/* ── Layout ── */
.block-container { max-width: 1080px; padding-top: 1.5rem; padding-bottom: 4rem; }

/* ── Page header ── */
.page-header { margin-bottom: 4px; }
.page-header h1 { font-size: 26px; font-weight: 700; color: #f0f0f0; margin: 0 0 4px 0; letter-spacing: -0.3px; }
.page-header p  { font-size: 14px; color: #5a5f72; margin: 0; }

/* ── Cards ── */
.card {
    background: #181b29;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 10px;
    border: 1px solid #1f2235;
    border-left: 4px solid #1f2235;
}
.card.critical { border-left-color: #ef4444; background: #1c1520; }
.card.high     { border-left-color: #f97316; background: #1c1a17; }
.card.medium   { border-left-color: #eab308; background: #1c1c15; }
.card.low      { border-left-color: #22c55e; background: #151c18; }
.card.clean    { border-left-color: #22c55e; background: #151c18; }
.card.info     { border-left-color: #3b82f6; background: #151824; }
.card.neutral  { border-left-color: #2a2d3e; }

/* ── Typography ── */
.label { font-size: 11px; color: #4a4f62; text-transform: uppercase; letter-spacing: 1.4px; margin-bottom: 8px; font-weight: 600; }
.big   { font-size: 42px; font-weight: 800; line-height: 1; letter-spacing: -1px; }
.plain { font-size: 14px; color: #9ca3af; line-height: 1.7; margin-top: 6px; }
.sub   { font-size: 12px; color: #4a4f62; margin-top: 3px; line-height: 1.4; }
.mono  { font-family: 'SF Mono', ui-monospace, 'Cascadia Code', monospace; font-size: 13px; }
.value { font-size: 15px; color: #d1d5db; font-weight: 500; margin-top: 4px; }
.verdict { font-size: 14px; font-weight: 600; margin-top: 14px; padding-top: 14px; border-top: 1px solid #1f2235; }

/* ── Badges ── */
.badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; margin: 2px; letter-spacing: 0.3px; }
.b-red { background: #ef444418; color: #ef4444; border: 1px solid #ef444440; }
.b-ora { background: #f9731618; color: #f97316; border: 1px solid #f9731640; }
.b-yel { background: #eab30818; color: #eab308; border: 1px solid #eab30840; }
.b-grn { background: #22c55e18; color: #22c55e; border: 1px solid #22c55e40; }
.b-blu { background: #3b82f618; color: #3b82f6; border: 1px solid #3b82f640; }
.b-gry { background: #6b728018; color: #6b7280; border: 1px solid #6b728040; }

/* ── Type tag (IOC labels) ── */
.type-tag {
    display: inline-block;
    background: #1f2235;
    color: #6b7280;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    padding: 2px 8px;
    border-radius: 4px;
    margin-right: 10px;
    vertical-align: middle;
    font-family: monospace;
}

/* ── IOC rows ── */
.ioc-row {
    background: #0f1120;
    border-radius: 8px;
    padding: 10px 16px;
    margin: 4px 0;
    font-family: 'SF Mono', ui-monospace, monospace;
    font-size: 13px;
    color: #c9d1e0;
    border: 1px solid #1a1d2e;
    display: flex;
    align-items: center;
}
.ioc-danger { color: #ef4444; }

/* ── Finding / Action items ── */
.finding {
    background: #141828;
    border-radius: 8px;
    padding: 12px 16px;
    margin: 5px 0;
    border-left: 3px solid #3b82f6;
    font-size: 14px;
    color: #c9d1e0;
    line-height: 1.6;
}
.action {
    background: #111c17;
    border-radius: 8px;
    padding: 12px 16px;
    margin: 5px 0;
    border-left: 3px solid #22c55e;
    font-size: 14px;
    color: #c9d1e0;
    line-height: 1.6;
}

/* ── Section headers ── */
.section {
    font-size: 12px;
    font-weight: 700;
    color: #4a4f62;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin: 32px 0 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid #1a1d2e;
}

/* ── Score bar ── */
.score-bar-track {
    background: #1a1d2e;
    border-radius: 6px;
    height: 8px;
    margin-top: 14px;
    overflow: hidden;
}
.score-bar-fill {
    height: 100%;
    border-radius: 6px;
    transition: width 0.3s ease;
}

/* ── Data grid ── */
.data-grid {
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    margin: 14px 0;
}
.data-cell { min-width: 80px; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #0d0f1a;
    border-right: 1px solid #1a1d2e;
}

/* ── Buttons ── */
.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    font-size: 14px;
    transition: opacity 0.15s;
}
.stButton > button:hover { opacity: 0.82; }

/* ── Inputs ── */
.stTextArea textarea, .stTextInput input {
    background: #0f1120 !important;
    border: 1px solid #1f2235 !important;
    border-radius: 8px !important;
    color: #e0e0e0 !important;
    font-size: 14px !important;
}
.stTextArea textarea:focus, .stTextInput input:focus {
    border-color: #3b82f6 !important;
}

/* ── Divider ── */
hr { border: none; border-top: 1px solid #1a1d2e; margin: 24px 0; }

/* ── Progress bar ── */
.stProgress > div > div { border-radius: 6px; }

/* ── Metric ── */
[data-testid="stMetric"] {
    background: #181b29;
    border-radius: 12px;
    padding: 16px 20px;
    border: 1px solid #1f2235;
}
[data-testid="stMetricValue"] { font-size: 28px !important; font-weight: 800 !important; }
[data-testid="stMetricLabel"] { font-size: 12px !important; color: #4a4f62 !important; text-transform: uppercase; letter-spacing: 1px; }

/* ── Expander ── */
[data-testid="stExpander"] {
    background: #181b29;
    border: 1px solid #1f2235;
    border-radius: 10px;
}

/* ── Radio ── */
.stRadio label { font-size: 14px !important; }

/* ── Caption ── */
.stCaption { color: #4a4f62 !important; font-size: 12px !important; }
</style>
""", unsafe_allow_html=True)


# ── Plain-language helpers ────────────────────────────────────────────────────

MITRE_PLAIN = {
    "T1566": "Attackers sent a deceptive message designed to trick the recipient into clicking a link or opening a file.",
    "T1204": "The email contains an attachment that requires the user to open or run it. This is a common way to install malware.",
    "T1059": "Evidence of scripting tools like PowerShell that attackers use to run commands and take control of a system.",
    "T1547": "Attackers may be attempting to keep malware running every time the computer starts up.",
    "T1056": "This looks like a credential harvesting attempt designed to steal a username and password.",
    "T1583": "The domain or infrastructure used was newly set up, which is common when attackers prepare for a campaign.",
    "T1036": "The sender is disguising themselves as a trusted source to gain the recipient's trust.",
    "T1027": "The content or files appear to be encoded or obfuscated to hide malicious intent from security tools.",
    "T1003": "Indicators suggest an attempt to extract saved credentials from the operating system.",
    "T1055": "Indicators suggest code may be injected into a running process to execute malicious actions.",
    "T1486": "Patterns consistent with ransomware were detected. Files may be at risk of being encrypted.",
    "T1070": "Evidence of attempts to delete logs or remove traces of malicious activity.",
    "T1562": "Indicators suggest security tools such as antivirus or the firewall may have been disabled.",
    "T1021": "Evidence of remote access tools being used to move laterally across systems.",
    "T1053": "A scheduled task may have been created to run malicious code automatically.",
    "T1105": "Indicators suggest tools or malware were downloaded from an external source.",
    "T1218": "A trusted Windows system binary was used to run malicious code and bypass security controls.",
    "T1082": "The attacker appears to be gathering information about the system and environment.",
    "T1190": "A known software vulnerability was referenced that could allow an attacker to compromise a system.",
    "T1078": "Indicators suggest legitimate account credentials may have been used or targeted by the attacker.",
}

SIGNAL_PLAIN = {
    "sender_mismatch":        "The From address and Reply-To address belong to different domains. This is a classic phishing trick.",
    "newly_registered_domain":"The domain was registered very recently. Attackers often register fresh domains right before launching a campaign.",
    "suspicious_url":         "A suspicious link was found in the content.",
    "vt_detections_3plus":    "Multiple cybersecurity companies flagged this as malicious.",
    "abuseipdb_score_50plus": "This IP address has been widely reported for malicious activity.",
    "urgency_language":       "The message uses high-pressure language to rush the recipient into acting without thinking.",
    "attachment_present":     "An attachment was found. Malicious files are commonly delivered as email attachments.",
    "cve_cvss_7plus":         "A known critical vulnerability was referenced. Attackers sometimes exploit these against unpatched systems.",
    "mitre_technique_mapped": "Known attacker techniques were identified in this content.",
    "spf_dkim_dmarc_fail":    "Email authentication checks failed. This email did not come from a legitimate server.",
}

LEVEL_ADVICE = {
    "Critical": "Strong evidence of malicious activity. Do not click any links, open attachments, or reply. Escalate to your security team immediately.",
    "High":     "Multiple threat indicators found. Treat this as likely malicious. Do not interact with any links or attachments. Report it.",
    "Medium":   "Some suspicious patterns detected. Proceed with caution and do not click links unless you can independently verify the sender.",
    "Low":      "Few or no threat indicators found. This appears relatively safe, but always verify unexpected messages with the sender directly.",
}

def _cls(level): return {"Critical":"critical","High":"high","Medium":"medium","Low":"low"}.get(level,"low")
def _col(s): return "#ff4b4b" if s>=76 else "#ff8c00" if s>=51 else "#ffd700" if s>=26 else "#21c55d"
def _badge(text, color): return f'<span class="badge b-{color}">{text}</span>'


# ── Core pipeline ─────────────────────────────────────────────────────────────

async def _enrich(parsed: dict) -> dict:
    iocs = parsed.get("iocs", {})
    vt_res, ab_res, nvd_res, wh_res, mb_res = [], [], [], [], []
    seen: set = set()

    for obj in iocs.get("ips", []):
        ip = obj["value"] if isinstance(obj, dict) else obj
        if ip not in seen:
            seen.add(ip)
            vt_res.append(await virustotal.lookup_ip(ip))
            ab_res.append(await abuseipdb.lookup_ip(ip))

    for obj in iocs.get("domains", []):
        d = obj["value"] if isinstance(obj, dict) else obj
        if d not in seen:
            seen.add(d)
            vt_res.append(await virustotal.lookup_domain(d))
            wh_res.append(whois_lookup.lookup_domain(d))

    for obj in iocs.get("urls", []):
        u = obj["value"] if isinstance(obj, dict) else obj
        if u not in seen:
            seen.add(u)
            vt_res.append(await virustotal.lookup_url(u))

    for cve in iocs.get("cves", []):
        if cve not in seen:
            seen.add(cve)
            nvd_res.append(await nvd.lookup_cve(cve))

    for obj in iocs.get("hashes", []):
        h = obj["value"] if isinstance(obj, dict) else obj
        if h not in seen:
            seen.add(h)
            mb_res.append(await malwarebazaar.lookup_hash(h))
            vt_res.append(await virustotal.lookup_hash(h))

    return {"vt_results": vt_res, "abuse_results": ab_res, "nvd_results": nvd_res, "whois_results": wh_res, "mb_results": mb_res}


def _run_full_analysis(parsed: dict) -> tuple:
    enrichment = asyncio.run(_enrich(parsed))
    parsed.update(enrichment)
    techniques = map_techniques(parsed)
    parsed["mitre_techniques"] = techniques
    score_result = score(parsed)
    parsed["score"] = score_result
    report = generate_report(parsed)
    return parsed, score_result, techniques, report


async def _single_lookup(value: str, ioc_type: str) -> dict:
    import re
    v = value.strip()
    if ioc_type == "IP" or (ioc_type == "Auto-detect" and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v)):
        return {"type":"ip", "vt": await virustotal.lookup_ip(v), "abuseipdb": await abuseipdb.lookup_ip(v)}
    if ioc_type == "Domain" or (ioc_type == "Auto-detect" and "." in v and not v.startswith("http")):
        return {"type":"domain", "vt": await virustotal.lookup_domain(v), "whois": whois_lookup.lookup_domain(v)}
    if ioc_type == "URL" or v.startswith("http"):
        return {"type":"url", "vt": await virustotal.lookup_url(v)}
    if ioc_type.startswith("Hash") or re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return {"type":"hash", "vt": await virustotal.lookup_hash(v)}
    if ioc_type == "CVE" or v.upper().startswith("CVE-"):
        return {"type":"cve", "nvd": await nvd.lookup_cve(v)}
    return {"type":"unknown", "error": "Could not detect the type. Please select it manually from the dropdown."}


# ── Render: score ─────────────────────────────────────────────────────────────

def _render_score(score_result: dict):
    s     = score_result["score"]
    level = score_result["level"]
    cls   = _cls(level)
    col   = _col(s)
    advice = LEVEL_ADVICE[level]

    st.markdown(f"""
    <div class="card {cls}">
        <div style="display:flex; align-items:flex-start; gap:32px; flex-wrap:wrap;">
            <div style="min-width:120px;">
                <div class="label">Risk Score</div>
                <div class="big" style="color:{col};">{s}<span style="font-size:20px; color:#2a2d3e; font-weight:400;">/100</span></div>
                <div style="margin-top:10px;">
                    <span class="badge {'b-red' if level=='Critical' else 'b-ora' if level=='High' else 'b-yel' if level=='Medium' else 'b-grn'}" style="font-size:13px; padding:5px 14px;">{level} Risk</span>
                </div>
                <div class="score-bar-track" style="width:120px;">
                    <div class="score-bar-fill" style="width:{s}%; background:{col};"></div>
                </div>
            </div>
            <div style="flex:1; min-width:200px; padding-left:32px; border-left:1px solid #1f2235;">
                <div class="label">What this means</div>
                <div class="plain" style="font-size:15px; color:#c9d1e0; margin-top:8px;">{advice}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def _render_breakdown(score_result: dict):
    st.markdown('<div class="section">Score Breakdown</div>', unsafe_allow_html=True)
    triggered = {k: v for k, v in score_result["breakdown"].items() if v > 0}
    clean     = {k: v for k, v in score_result["breakdown"].items() if v == 0}

    if triggered:
        for signal, pts in triggered.items():
            plain = SIGNAL_PLAIN.get(signal, signal.replace("_", " ").title())
            st.markdown(f"""
            <div class="card high" style="padding:14px 20px; display:flex; justify-content:space-between; align-items:center; gap:16px;">
                <div style="flex:1;">
                    <div style="font-weight:600; font-size:14px; color:#e0e0e0;">{signal.replace('_',' ').title()}</div>
                    <div class="plain" style="margin-top:3px; font-size:13px;">{plain}</div>
                </div>
                <div style="font-size:20px; font-weight:800; color:#f97316; min-width:42px; text-align:right;">+{pts}</div>
            </div>
            """, unsafe_allow_html=True)

    if clean:
        with st.expander(f"{len(clean)} signals not triggered"):
            for signal in clean:
                st.markdown(f'<div style="font-size:13px; color:#4a4f62; padding:4px 0;">{signal.replace("_"," ").title()}</div>', unsafe_allow_html=True)


def _render_mitre(techniques: list):
    st.markdown('<div class="section">MITRE ATT&CK Techniques</div>', unsafe_allow_html=True)
    if not techniques:
        st.markdown('<div class="card neutral"><div class="plain">No known attack techniques matched in this content.</div></div>', unsafe_allow_html=True)
        return
    st.markdown('<div class="plain" style="margin-bottom:14px; font-size:13px;">Techniques from the MITRE ATT&CK framework — a globally recognized catalog of real attacker behavior. These are investigative signals, not confirmed attacks.</div>', unsafe_allow_html=True)
    for t in techniques:
        plain = MITRE_PLAIN.get(t["id"], "A known attacker technique was detected.")
        conf_cls = "b-red" if t["confidence"] == "high" else "b-yel" if t["confidence"] == "medium" else "b-gry"
        st.markdown(f"""
        <div class="card medium" style="padding:16px 20px;">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
                <div style="display:flex; align-items:center; gap:12px;">
                    <span class="mono" style="color:#eab308; font-weight:700; font-size:14px;">{t['id']}</span>
                    <span style="color:#e0e0e0; font-weight:600; font-size:14px;">{t['name']}</span>
                </div>
                <span class="badge {conf_cls}">{t['confidence'].capitalize()} confidence</span>
            </div>
            <div class="plain" style="margin-top:10px; font-size:13px;">{plain}</div>
            <div style="margin-top:10px;">
                <a href="{t['url']}" target="_blank" style="font-size:12px; color:#3b82f6; text-decoration:none;">View on MITRE ATT&CK</a>
            </div>
        </div>
        """, unsafe_allow_html=True)


def _render_iocs(parsed: dict):
    st.markdown('<div class="section">Extracted Indicators (IOCs)</div>', unsafe_allow_html=True)
    st.markdown('<div class="plain" style="margin-bottom:14px; font-size:13px;">Suspicious items found in the content. URLs and domains are defanged (brackets added) so they cannot be accidentally clicked.</div>', unsafe_allow_html=True)

    iocs = parsed.get("iocs", {})
    type_tags = {
        "urls":    "URL",
        "domains": "DOMAIN",
        "ips":     "IP",
        "hashes":  "HASH",
        "cves":    "CVE",
        "emails":  "EMAIL",
    }
    any_found = False
    for key, tag in type_tags.items():
        items = iocs.get(key, [])
        if not items:
            continue
        any_found = True
        for item in items:
            val = item.get("defanged", item.get("value", item)) if isinstance(item, dict) else item
            st.markdown(f'<div class="ioc-row"><span class="type-tag">{tag}</span>{val}</div>', unsafe_allow_html=True)

    attachments = parsed.get("attachments", [])
    if attachments:
        for a in attachments:
            danger = any(a.lower().endswith(ext) for ext in [".exe",".js",".vbs",".bat",".ps1",".hta",".docm",".xlsm",".zip",".rar"])
            warn = ' <span style="color:#ef4444; font-size:12px; font-weight:600;">Dangerous file type</span>' if danger else ""
            st.markdown(f'<div class="ioc-row"><span class="type-tag">ATTACHMENT</span><span class="{"ioc-danger" if danger else ""}">{a}</span>{warn}</div>', unsafe_allow_html=True)
        any_found = True

    if not any_found:
        st.markdown('<div class="card neutral"><div class="plain">No indicators were extracted from this content.</div></div>', unsafe_allow_html=True)


def _render_enrichment(parsed: dict):
    st.markdown('<div class="section">Threat Intelligence</div>', unsafe_allow_html=True)

    vt  = [r for r in parsed.get("vt_results",    []) if not r.get("skipped")]
    ab  = [r for r in parsed.get("abuse_results",  []) if not r.get("skipped")]
    wh  =  parsed.get("whois_results", [])
    nv  = [r for r in parsed.get("nvd_results",   []) if not r.get("skipped")]
    mb  = [r for r in parsed.get("mb_results",    []) if not r.get("skipped")]
    skipped = [r for r in
               parsed.get("vt_results", []) + parsed.get("abuse_results", []) +
               parsed.get("nvd_results", []) + parsed.get("mb_results", [])
               if r.get("skipped")]

    if not any([vt, ab, wh, nv, mb]):
        st.markdown('<div class="card info"><div class="plain">No threat intelligence results returned. Indicators may be unknown, or enrichment was skipped due to offline mode or missing API keys.</div></div>', unsafe_allow_html=True)
        return

    for r in vt:
        mal   = r.get("malicious",  0)
        sus   = r.get("suspicious", 0)
        har   = r.get("harmless",   0)
        total = mal + sus + har
        cls   = "critical" if mal >= 5 else "high" if mal >= 3 else "medium" if mal >= 1 else "clean"
        if mal >= 5:   verdict, vc = "Highly malicious. Flagged by many security vendors. Avoid all interaction.", "#ef4444"
        elif mal >= 3: verdict, vc = "Likely malicious. Flagged by multiple vendors.", "#f97316"
        elif mal >= 1: verdict, vc = "Possibly suspicious. Flagged by at least one vendor. Investigate further.", "#eab308"
        else:          verdict, vc = "No vendors flagged this. Appears clean, though this does not guarantee safety.", "#22c55e"
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">VirusTotal</div>
            <div class="mono" style="color:#9ca3af; margin-bottom:14px; font-size:12px;">{r.get('ioc','')}</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">Flagged by</div>
                    <div style="font-size:32px; font-weight:800; color:#ef4444; line-height:1;">{mal}</div>
                    <div class="sub">of {total} vendors</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Suspicious</div>
                    <div style="font-size:24px; font-weight:700; color:#f97316; line-height:1.2;">{sus}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Clean</div>
                    <div style="font-size:24px; font-weight:700; color:#22c55e; line-height:1.2;">{har}</div>
                </div>
            </div>
            <div class="verdict" style="color:{vc};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    for r in ab:
        conf    = r.get("abuse_confidence", 0)
        reports = r.get("total_reports",    0)
        cls     = "critical" if conf >= 75 else "high" if conf >= 50 else "medium" if conf >= 25 else "clean"
        col     = "#ef4444" if conf >= 75 else "#f97316" if conf >= 50 else "#eab308" if conf >= 25 else "#22c55e"
        if conf >= 75:   verdict = f"Widely known as malicious. Reported {reports} times by the security community."
        elif conf >= 50: verdict = f"High abuse score. Reported {reports} times. Treat as malicious unless proven otherwise."
        elif conf >= 25: verdict = f"Some abuse history. {reports} reports on record. Approach with caution."
        else:            verdict = f"Low abuse history. Only {reports} reports. Appears relatively safe."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">AbuseIPDB — IP Reputation</div>
            <div class="mono" style="color:#9ca3af; margin-bottom:14px; font-size:12px;">{r.get('ioc','')}</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">Abuse Confidence</div>
                    <div style="font-size:36px; font-weight:800; color:{col}; line-height:1;">{conf}<span style="font-size:18px;">%</span></div>
                    <div class="sub">0% clean / 100% malicious</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Total Reports</div>
                    <div style="font-size:24px; font-weight:700; color:#e0e0e0; line-height:1.2;">{reports}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Country</div>
                    <div class="value">{r.get('country','?')}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">ISP</div>
                    <div class="value" style="font-size:13px;">{r.get('isp','unknown')}</div>
                </div>
            </div>
            <div class="verdict" style="color:{col};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    for r in wh:
        age = r.get("age_days")
        new = r.get("newly_registered", False)
        cls = "high" if new else "low"
        age_str = f"{age} days" if age is not None else "unknown"
        col = "#f97316" if new else "#22c55e"
        if new:              verdict = f"Registered only {age} days ago. Newly created domains are a major red flag. Attackers often set them up right before launching a campaign."
        elif age and age < 180: verdict = f"Relatively new domain at {age} days old. Not necessarily malicious, but worth noting."
        else:                verdict = f"Established domain at {age_str}. Older domains are generally more trustworthy."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">WHOIS — Domain Registration</div>
            <div class="mono" style="color:#9ca3af; margin-bottom:14px; font-size:12px;">{r.get('domain','')}</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">Domain Age</div>
                    <div style="font-size:24px; font-weight:700; color:{col}; line-height:1.2;">{age_str}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Registered On</div>
                    <div class="value" style="font-size:13px;">{r.get('creation_date','unknown')}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Registrar</div>
                    <div class="value" style="font-size:13px;">{r.get('registrar','unknown')}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Country</div>
                    <div class="value">{r.get('country','unknown')}</div>
                </div>
            </div>
            <div class="verdict" style="color:{col};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    for r in nv:
        cvss = r.get("cvss_score", 0)
        sev  = r.get("severity", "unknown").capitalize()
        cls  = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
        col  = "#ef4444" if cvss >= 9 else "#f97316" if cvss >= 7 else "#eab308" if cvss >= 4 else "#22c55e"
        if cvss >= 9:   verdict = "Critical severity. Unpatched systems are at serious risk of compromise."
        elif cvss >= 7: verdict = "High severity. This vulnerability can be actively exploited. Patching is urgent."
        elif cvss >= 4: verdict = "Medium severity. Should be patched but not an immediate emergency."
        else:           verdict = "Low severity vulnerability."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">NVD — Known Vulnerability</div>
            <div class="mono" style="color:#9ca3af; margin-bottom:14px; font-size:12px;">{r.get('ioc','')}</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">CVSS Score (0-10)</div>
                    <div style="font-size:36px; font-weight:800; color:{col}; line-height:1;">{cvss}</div>
                    <div class="sub">{sev}</div>
                </div>
                <div class="data-cell" style="flex:2;">
                    <div class="sub">Description</div>
                    <div style="font-size:13px; color:#9ca3af; margin-top:4px; line-height:1.6;">{r.get('description','No description available.')}</div>
                </div>
            </div>
            <div class="verdict" style="color:{col};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    for r in mb:
        found = r.get("found", False)
        cls   = "critical" if found else "clean"
        tags  = ", ".join(r.get("tags", [])) or "none"
        col   = "#ef4444" if found else "#22c55e"
        verdict = f"Found in MalwareBazaar. Classified as {r.get('signature','unknown')}. First seen {r.get('first_seen','?')}." if found else "Not found in MalwareBazaar. The file may be clean or not yet cataloged."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">MalwareBazaar — File Hash</div>
            <div class="mono" style="color:#9ca3af; margin-bottom:14px; font-size:12px;">{r.get('ioc','')[:40]}...</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">Known Malware</div>
                    <div style="font-size:20px; font-weight:800; color:{col};">{"YES" if found else "NOT FOUND"}</div>
                </div>
                {"<div class='data-cell'><div class='sub'>Malware Family</div><div class='value'>" + r.get('signature','?') + "</div></div>" if found else ""}
                {"<div class='data-cell'><div class='sub'>File Type</div><div class='value'>" + r.get('file_type','?') + "</div></div>" if found else ""}
                {"<div class='data-cell'><div class='sub'>Tags</div><div class='value' style='font-size:13px;'>" + tags + "</div></div>" if found else ""}
            </div>
            <div class="verdict" style="color:{col};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    if skipped:
        with st.expander(f"{len(skipped)} lookup(s) skipped"):
            for r in skipped:
                st.caption(f"{r.get('source','')} / {r.get('ioc','')} — {r.get('reason','')}")


def _render_report(report: dict):
    st.markdown('<div class="section">AI Investigation Report</div>', unsafe_allow_html=True)
    summary = report.get("executive_summary", "")
    if summary:
        st.markdown(f"""
        <div class="card info">
            <div class="label">Summary</div>
            <div style="font-size:15px; color:#c9d1e0; line-height:1.7; margin-top:8px;">{summary}</div>
        </div>
        """, unsafe_allow_html=True)

    findings = report.get("technical_findings", [])
    if findings:
        st.markdown('<div class="sub" style="margin:16px 0 8px; font-size:12px; text-transform:uppercase; letter-spacing:1px;">Technical Findings</div>', unsafe_allow_html=True)
        for f in findings:
            st.markdown(f'<div class="finding">{f}</div>', unsafe_allow_html=True)

    actions = report.get("recommended_actions", [])
    if actions:
        st.markdown('<div class="sub" style="margin:16px 0 8px; font-size:12px; text-transform:uppercase; letter-spacing:1px;">Recommended Actions</div>', unsafe_allow_html=True)
        for a in actions:
            st.markdown(f'<div class="action">{a}</div>', unsafe_allow_html=True)

    notes = report.get("analyst_notes", "")
    if notes:
        st.markdown(f'<div class="card neutral" style="margin-top:12px;"><div class="label">Analyst Notes</div><div class="plain" style="font-size:13px;">{notes}</div></div>', unsafe_allow_html=True)


def _render_ioc_lookup(result: dict):
    if result.get("error"):
        st.error(result["error"])
        return

    vt = result.get("vt", {})
    if vt and not vt.get("skipped"):
        mal   = vt.get("malicious",  0)
        sus   = vt.get("suspicious", 0)
        har   = vt.get("harmless",   0)
        total = mal + sus + har
        cls   = "critical" if mal >= 5 else "high" if mal >= 3 else "medium" if mal >= 1 else "clean"
        col   = "#ef4444" if mal >= 3 else "#eab308" if mal >= 1 else "#22c55e"
        if mal >= 5:   verdict = "Highly dangerous. Multiple security vendors confirmed this as malicious."
        elif mal >= 3: verdict = "Likely malicious. Flagged by multiple security vendors."
        elif mal >= 1: verdict = "Possibly suspicious. Flagged by at least one vendor. Investigate before trusting."
        else:          verdict = "No vendors flagged this. Appears clean, though this does not guarantee safety."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">VirusTotal</div>
            <div class="sub" style="margin-bottom:14px;">Checks against 70+ antivirus and security vendors simultaneously.</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">Flagged malicious by</div>
                    <div style="font-size:40px; font-weight:800; color:#ef4444; line-height:1;">{mal}</div>
                    <div class="sub">of {total} vendors</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Suspicious</div>
                    <div style="font-size:28px; font-weight:700; color:#f97316; line-height:1.2;">{sus}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Clean</div>
                    <div style="font-size:28px; font-weight:700; color:#22c55e; line-height:1.2;">{har}</div>
                </div>
            </div>
            <div class="verdict" style="color:{col};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)
    elif vt and vt.get("skipped"):
        st.markdown(f'<div class="card neutral"><div class="label">VirusTotal</div><div class="plain">Skipped: {vt.get("reason","")}</div></div>', unsafe_allow_html=True)

    ab = result.get("abuseipdb", {})
    if ab and not ab.get("skipped"):
        conf    = ab.get("abuse_confidence", 0)
        reports = ab.get("total_reports",    0)
        cls     = "critical" if conf >= 75 else "high" if conf >= 50 else "medium" if conf >= 25 else "clean"
        col     = "#ef4444" if conf >= 75 else "#f97316" if conf >= 50 else "#eab308" if conf >= 25 else "#22c55e"
        if conf >= 75:   verdict = f"Widely known as malicious. Reported {reports} times. Block this IP."
        elif conf >= 50: verdict = f"High abuse score. Reported {reports} times. Treat as malicious."
        elif conf >= 25: verdict = f"Some abuse history with {reports} reports. Approach with caution."
        else:            verdict = f"Low abuse history with {reports} reports. Appears relatively safe."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">AbuseIPDB — IP Reputation</div>
            <div class="sub" style="margin-bottom:14px;">Community-driven database of malicious IP addresses reported by security researchers.</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">Abuse Confidence</div>
                    <div style="font-size:44px; font-weight:800; color:{col}; line-height:1;">{conf}<span style="font-size:22px;">%</span></div>
                    <div class="sub">0% clean / 100% malicious</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Total Reports</div>
                    <div style="font-size:28px; font-weight:700; color:#e0e0e0; line-height:1.2;">{reports}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">ISP</div>
                    <div class="value" style="font-size:13px;">{ab.get('isp','unknown')}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Country</div>
                    <div class="value">{ab.get('country','unknown')}</div>
                </div>
            </div>
            <div class="verdict" style="color:{col};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    wh = result.get("whois", {})
    if wh:
        age     = wh.get("age_days")
        new     = wh.get("newly_registered", False)
        age_str = f"{age} days" if age is not None else "unknown"
        col     = "#f97316" if new else "#22c55e"
        if new:              verdict = f"Registered only {age} days ago. Newly created domains are a major red flag in phishing campaigns."
        elif age and age < 180: verdict = f"Relatively new at {age} days. Not automatically malicious but worth noting."
        else:                verdict = "Established domain. Older domains are generally more trustworthy."
        st.markdown(f"""
        <div class="card {'high' if new else 'low'}">
            <div class="label">WHOIS — Domain Registration</div>
            <div class="sub" style="margin-bottom:14px;">Shows when the domain was first registered. Attackers often create fresh domains right before launching an attack.</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">Domain Age</div>
                    <div style="font-size:28px; font-weight:800; color:{col}; line-height:1.2;">{age_str}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Registered On</div>
                    <div class="value" style="font-size:13px;">{wh.get('creation_date','unknown')}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Registrar</div>
                    <div class="value" style="font-size:13px;">{wh.get('registrar','unknown')}</div>
                </div>
                <div class="data-cell">
                    <div class="sub">Country</div>
                    <div class="value">{wh.get('country','unknown')}</div>
                </div>
            </div>
            <div class="verdict" style="color:{col};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    nvd_r = result.get("nvd", {})
    if nvd_r and not nvd_r.get("skipped"):
        cvss = nvd_r.get("cvss_score", 0)
        sev  = nvd_r.get("severity", "?").capitalize()
        cls  = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
        col  = "#ef4444" if cvss >= 9 else "#f97316" if cvss >= 7 else "#eab308" if cvss >= 4 else "#22c55e"
        if cvss >= 9:   verdict = "Critical severity. Unpatched systems are at serious risk. Patch immediately."
        elif cvss >= 7: verdict = "High severity. This flaw can be actively exploited. Patching is urgent."
        elif cvss >= 4: verdict = "Medium severity. Should be patched but not an immediate emergency."
        else:           verdict = "Low severity vulnerability."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">NVD — Known Vulnerability</div>
            <div class="sub" style="margin-bottom:14px;">The National Vulnerability Database tracks publicly known security flaws. Scores range from 0 (low risk) to 10 (critical).</div>
            <div class="data-grid">
                <div class="data-cell">
                    <div class="sub">CVSS Score</div>
                    <div style="font-size:44px; font-weight:800; color:{col}; line-height:1;">{cvss}</div>
                    <div class="sub">out of 10 / {sev}</div>
                </div>
                <div class="data-cell" style="flex:2;">
                    <div class="sub">Description</div>
                    <div style="font-size:13px; color:#9ca3af; margin-top:6px; line-height:1.6;">{nvd_r.get('description','No description available.')}</div>
                </div>
            </div>
            <div class="verdict" style="color:{col};">{verdict}</div>
        </div>
        """, unsafe_allow_html=True)
    elif nvd_r and nvd_r.get("skipped"):
        st.markdown(f'<div class="card neutral"><div class="label">NVD</div><div class="plain">Skipped: {nvd_r.get("reason","")}</div></div>', unsafe_allow_html=True)


def _build_md(parsed: dict, score_result: dict, techniques: list, report: dict) -> str:
    subject = parsed.get("subject", "alert")[:40].replace("/", "-")
    lines = [
        f"# ThreatScope Report — {subject}",
        f"**Date:** {datetime.now().isoformat()}",
        f"**Risk Score:** {score_result['score']}/100 ({score_result['level']})",
        "", "## Executive Summary", report.get("executive_summary", ""),
        "", "## Technical Findings", *[f"- {f}" for f in report.get("technical_findings", [])],
        "", "## MITRE ATT&CK Techniques",
        *[f"- **[{t['id']}] {t['name']}** ({t['confidence']} confidence) — {MITRE_PLAIN.get(t['id'],'')}" for t in techniques],
        "", "## Score Breakdown",
        *[f"- {k.replace('_',' ').title()}: +{v}" for k, v in score_result['breakdown'].items() if v > 0],
        "", "## Recommended Actions", *[f"- {a}" for a in report.get("recommended_actions", [])],
        "", "## Analyst Notes", report.get("analyst_notes", ""),
        "", "---",
        "_Generated by ThreatScope. All findings require human review before taking action._",
        "_Defensive security education only._",
    ]
    return "\n".join(lines)

def _render_header_visualizer(parsed: dict):
    hops = parsed.get("received_hops", 0)
    spf  = parsed.get("spf", "unknown")
    dkim = parsed.get("dkim", "unknown")
    dmarc= parsed.get("dmarc", "unknown")

    if not hops and spf == "unknown":
        return

    st.markdown('<div class="section">Email Header Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="plain" style="margin-bottom:10px;">Email headers reveal the true path a message took to reach you. Failures in authentication checks (SPF, DKIM, DMARC) are strong indicators the email is not from who it claims to be.</div>', unsafe_allow_html=True)

    def _auth_badge(name, val):
        if val == "pass": return f'<span class="badge b-grn">{name}: PASS</span>'
        if val == "fail": return f'<span class="badge b-red">{name}: FAIL</span>'
        return f'<span class="badge b-gry">{name}: {val.upper()}</span>'

    auth_html = _auth_badge("SPF", spf) + _auth_badge("DKIM", dkim) + _auth_badge("DMARC", dmarc)
    mismatch = parsed.get("sender_mismatch", False)

    st.markdown(f"""
    <div class="card {'critical' if (spf=='fail' and dkim=='fail') else 'medium' if (spf=='fail' or dkim=='fail') else 'clean'}">
        <div class="label">Authentication Results</div>
        <div style="margin:10px 0;">{auth_html}</div>
        <div class="plain">
            {'All three authentication checks failed. This email almost certainly did not come from a legitimate server.' if spf=='fail' and dkim=='fail' and dmarc=='fail'
             else 'One or more authentication checks failed. Treat this email with suspicion.' if 'fail' in [spf,dkim,dmarc]
             else 'Authentication checks passed.'}
        </div>
    </div>
    """, unsafe_allow_html=True)

    if mismatch:
        frm  = parsed.get("from", "unknown")
        rply = parsed.get("reply_to", "unknown")
        st.markdown(f"""
        <div class="card high" style="margin-top:8px;">
            <div class="label">Sender Domain Mismatch</div>
            <div style="display:flex;gap:20px;margin:10px 0;flex-wrap:wrap;">
                <div><div class="sub">From</div><div class="mono" style="color:#ff8c00;">{frm}</div></div>
                <div style="font-size:20px;color:#555;align-self:center;">≠</div>
                <div><div class="sub">Reply-To</div><div class="mono" style="color:#ff4b4b;">{rply}</div></div>
            </div>
            <div class="plain">The From address and Reply-To address belong to different domains. Replies to this email go to the attacker, not the claimed sender.</div>
        </div>
        """, unsafe_allow_html=True)

    if hops:
        st.markdown(f"""
        <div class="card info" style="margin-top:8px;">
            <div class="label">Routing Hops</div>
            <div style="font-size:22px;font-weight:700;margin:6px 0;">{hops} server hop{"s" if hops != 1 else ""}</div>
            <div class="plain">This email passed through {hops} mail server{"s" if hops != 1 else ""} before arriving. Unusually long routing chains can indicate spoofing or relay abuse.</div>
        </div>
        """, unsafe_allow_html=True)


def _save_report(parsed: dict, score_result: dict, techniques: list, report: dict):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    subject = parsed.get("subject", "alert")[:40].replace("/", "-")
    md_content = _build_md(parsed, score_result, techniques, report)
    filename = REPORTS_DIR / f"{ts}_{subject}.md"
    filename.write_text(md_content)

    col1, col2 = st.columns([3, 1])
    with col1:
        st.success(f"Report saved: `{filename.name}`")
    with col2:
        _pdf_download_button(md_content, f"{ts}_{subject}.pdf")

def _pdf_download_button(md_content: str, filename: str):
    try:
        from markdown import markdown
        from weasyprint import HTML
        html = markdown(md_content, extensions=["tables", "fenced_code"])
        styled = f"""
        <html><head><style>
        body {{ font-family: sans-serif; padding: 40px; color: #111; }}
        h1 {{ color: #1a1a2e; }} h2 {{ color: #16213e; border-bottom: 1px solid #ccc; padding-bottom: 4px; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }}
        </style></head><body>{html}</body></html>
        """
        pdf_bytes = HTML(string=styled).write_pdf()
        st.download_button("⬇️ Download PDF", pdf_bytes, file_name=filename, mime="application/pdf")
    except Exception:
        st.caption("PDF export unavailable — install weasyprint system deps to enable.")


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="padding: 10px 0 20px 0;">
        <div style="font-size:22px; font-weight:800; color:#f0f0f0; letter-spacing:-0.5px;">ThreatScope</div>
        <div style="font-size:12px; color:#555; margin-top:2px;">Local-first security triage</div>
    </div>
    """, unsafe_allow_html=True)

    page = st.selectbox("", [
        "Dashboard",
        "Email Analyzer",
        "Batch Analysis",
        "IOC Lookup",
        "Alert Triage",
        "Reports",
        "Settings",
    ], label_visibility="collapsed")

    st.markdown("<div style='margin-top:24px;'></div>", unsafe_allow_html=True)

    def _status_dot(ok): return f"<span style='color:{'#21c55d' if ok else '#ff4b4b'};'>{'●' if ok else '●'}</span>"

    st.markdown(f"""
    <div style="font-size:12px; color:#555; margin-bottom:8px; text-transform:uppercase; letter-spacing:1px;">Integrations</div>
    <div style="font-size:13px; line-height:2; color:#888;">
        {_status_dot(bool(config.VT_API_KEY))} VirusTotal<br>
        {_status_dot(bool(config.ABUSEIPDB_API_KEY))} AbuseIPDB<br>
        {_status_dot(bool(config.MB_API_KEY))} MalwareBazaar<br>
        {_status_dot(bool(config.NVD_API_KEY))} NVD
    </div>
    <div style="margin-top:16px; font-size:12px; color:#555; line-height:1.6;">
        Model: <span style="color:#888;">{config.OLLAMA_MODEL}</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top:auto; padding-top:40px;'></div>", unsafe_allow_html=True)
    st.markdown("<div style='font-size:11px; color:#444; line-height:1.6;'>All findings require human review before taking action.</div>", unsafe_allow_html=True)


# ── Dashboard ────────────────────────────────────────────────────────────────
if page == "Dashboard":
    st.markdown('<div class="page-header"><h1>Dashboard</h1><p>Overview of all analyses run with ThreatScope.</p></div>', unsafe_allow_html=True)
    st.markdown("---")

    reports = sorted(REPORTS_DIR.glob("*.md"), reverse=True)

    if not reports:
        st.info("No analyses yet. Run your first analysis on the Email Analyzer or Alert Triage page.")
    else:
        scores, levels, dates = [], [], []
        for r in reports:
            text = r.read_text()
            import re as _re
            score_match = _re.search(r"\*\*Risk Score:\*\* (\d+)/100 \((\w+)\)", text)
            date_match  = _re.search(r"\*\*Date:\*\* ([\d\-T:\.]+)", text)
            if score_match:
                scores.append(int(score_match.group(1)))
                levels.append(score_match.group(2))
            if date_match:
                try:
                    dates.append(datetime.fromisoformat(date_match.group(1)))
                except Exception:
                    pass

        total = len(reports)
        avg   = round(sum(scores) / len(scores), 1) if scores else 0
        critical = levels.count("Critical")
        high     = levels.count("High")
        medium   = levels.count("Medium")
        low      = levels.count("Low")

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Analyses", total)
        c2.metric("Avg Risk Score", avg)
        c3.metric("Critical", critical)
        c4.metric("High", high)
        c5.metric("Medium / Low", f"{medium} / {low}")

        st.markdown("---")
        st.subheader("Risk Level Distribution")
        if levels:
            import pandas as pd
            dist = {"Critical": critical, "High": high, "Medium": medium, "Low": low}
            df = pd.DataFrame({"Level": list(dist.keys()), "Count": list(dist.values())})
            st.bar_chart(df.set_index("Level"))

        st.markdown("---")
        st.subheader("Recent Analyses")
        for r in reports[:10]:
            text = r.read_text()
            score_match = _re.search(r"\*\*Risk Score:\*\* (\d+)/100 \((\w+)\)", text)
            s = int(score_match.group(1)) if score_match else 0
            lv = score_match.group(2) if score_match else "?"
            col = {"Critical":"#ff4b4b","High":"#ff8c00","Medium":"#ffd700","Low":"#21c55d"}.get(lv,"#aaa")
            mtime = datetime.fromtimestamp(r.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            st.markdown(f"""
            <div class="card" style="padding:10px 16px;display:flex;justify-content:space-between;align-items:center;">
                <div><div style="font-size:13px;font-weight:600;">{r.stem[:60]}</div><div class="sub">{mtime}</div></div>
                <div style="font-size:22px;font-weight:800;color:{col};">{s}<span style="font-size:12px;color:#555;">/100</span></div>
            </div>
            """, unsafe_allow_html=True)


# ── Batch Analysis ────────────────────────────────────────────────────────────
elif page == "Batch Analysis":
    st.markdown('<div class="page-header"><h1>Batch Analysis</h1><p>Upload multiple .eml files at once and get a full results summary.</p></div>', unsafe_allow_html=True)
    st.markdown("---")

    uploaded_files = st.file_uploader(
        "Upload .eml files",
        type=["eml"],
        accept_multiple_files=True,
    )

    if st.button("Analyze All", type="primary") and uploaded_files:
        results = []
        total_files = len(uploaded_files)
        overall_bar  = st.progress(0, text=f"Analyzing 0 of {total_files} files...")
        file_bar     = st.progress(0, text="")
        info         = st.empty()

        for i, f in enumerate(uploaded_files):
            overall_bar.progress(int((i / total_files) * 100), text=f"File {i+1} of {total_files}: {f.name}")

            info.caption("Parsing email...")
            file_bar.progress(10, text="Parsing...")
            raw = f.read().decode("utf-8", errors="replace")
            parsed = parse_raw_email(raw)

            info.caption("Checking threat intelligence...")
            file_bar.progress(30, text="Threat intel lookups...")
            enrichment = asyncio.run(_enrich(parsed))
            parsed.update(enrichment)

            info.caption("Mapping techniques and scoring...")
            file_bar.progress(65, text="Scoring...")
            techniques = map_techniques(parsed)
            parsed["mitre_techniques"] = techniques
            score_result = score(parsed)
            parsed["score"] = score_result

            info.caption("Generating AI report...")
            file_bar.progress(80, text="Generating report...")
            report = generate_report(parsed)

            _save_report(parsed, score_result, techniques, report)
            results.append({
                "File": f.name,
                "Subject": parsed.get("subject", "unknown")[:50],
                "Score": score_result["score"],
                "Level": score_result["level"],
                "Sender Mismatch": "Yes" if parsed.get("sender_mismatch") else "No",
                "IOCs Found": sum(len(v) for v in parsed.get("iocs", {}).values()),
                "MITRE Techniques": len(techniques),
            })
            file_bar.progress(100, text=f"Done: {score_result['score']}/100 ({score_result['level']})")

        overall_bar.progress(100, text=f"All {total_files} files analyzed.")
        file_bar.empty()
        info.empty()

        st.markdown("---")
        st.subheader("Batch Results Summary")
        import pandas as pd
        df = pd.DataFrame(results)
        st.dataframe(
            df.style.map(
                lambda v: "color: #ff4b4b; font-weight: bold" if v == "Critical"
                else "color: #ff8c00; font-weight: bold" if v == "High"
                else "color: #ffd700" if v == "Medium"
                else "color: #21c55d" if v == "Low" else "",
                subset=["Level"]
            ),
            use_container_width=True,
        )
        st.caption("Full reports for each file have been saved to the Reports page.")

    elif not uploaded_files:
        st.info("Upload one or more .eml files above then click Analyze All.")


# ── Email Analyzer ────────────────────────────────────────────────────────────
elif page == "Email Analyzer":
    st.markdown('<div class="page-header"><h1>Email Analyzer</h1><p>Paste a suspicious email to extract IOCs, check threat intelligence, and generate a security report.</p></div>', unsafe_allow_html=True)
    st.markdown("---")

    if "email_text_area" not in st.session_state:
        st.session_state["email_text_area"] = ""

    input_method = st.radio("Input method", ["Paste raw email", "Upload .eml file"], horizontal=True)

    col1, col2, col3 = st.columns([2, 2, 6])
    with col1:
        analyze = st.button("Analyze", type="primary", use_container_width=True)
    with col2:
        if st.button("Load Sample", use_container_width=True):
            if SAMPLE_PATH.exists():
                st.session_state["email_text_area"] = SAMPLE_PATH.read_text()
            else:
                st.error("Sample file not found.")

    if input_method == "Paste raw email":
        raw_email = st.text_area(
            "Email content",
            height=250,
            placeholder="Paste the full email here, including headers if available...",
            key="email_text_area",
        )
    else:
        uploaded = st.file_uploader("Upload .eml file", type=["eml"])
        raw_email = uploaded.read().decode("utf-8", errors="replace") if uploaded else ""

    if analyze and raw_email:
        bar  = st.progress(0, text="Starting analysis...")
        info = st.empty()

        info.caption("Parsing email structure and headers...")
        bar.progress(10, text="Parsing email...")
        parsed = parse_raw_email(raw_email)

        info.caption("Checking IPs, domains, and URLs against threat databases. This may take a moment...")
        bar.progress(25, text="Running threat intelligence lookups...")
        enrichment = asyncio.run(_enrich(parsed))
        parsed.update(enrichment)

        info.caption("Mapping to MITRE ATT&CK framework...")
        bar.progress(60, text="Mapping attack techniques...")
        techniques = map_techniques(parsed)
        parsed["mitre_techniques"] = techniques

        info.caption("Calculating risk score...")
        bar.progress(70, text="Scoring...")
        score_result = score(parsed)
        parsed["score"] = score_result

        info.caption("Generating AI investigation report. This is the slowest step — usually 30 to 90 seconds depending on your hardware...")
        bar.progress(75, text="Generating AI report — please wait...")
        report = generate_report(parsed)

        bar.progress(100, text="Analysis complete.")
        info.empty()
        bar.empty()

        st.markdown("---")
        _render_score(score_result)
        st.markdown("---")
        _render_header_visualizer(parsed)
        st.markdown("---")
        col_l, col_r = st.columns(2)
        with col_l:
            _render_breakdown(score_result)
        with col_r:
            _render_mitre(techniques)
        st.markdown("---")
        _render_iocs(parsed)
        st.markdown("---")
        _render_enrichment(parsed)
        st.markdown("---")
        _render_report(report)
        st.markdown("---")
        _save_report(parsed, score_result, techniques, report)

    elif analyze:
        st.warning("Please paste an email or load the sample first.")


# ── IOC Lookup ────────────────────────────────────────────────────────────────
elif page == "IOC Lookup":
    st.markdown('<div class="page-header"><h1>IOC Lookup</h1><p>Check an IP address, domain, URL, file hash, or CVE against threat intelligence databases.</p></div>', unsafe_allow_html=True)
    st.markdown("---")

    col1, col2 = st.columns([3, 1])
    with col1:
        ioc_input = st.text_input("What do you want to check?", placeholder="e.g.  81.19.219.221   or   evil.com   or   CVE-2021-44228")
    with col2:
        ioc_type = st.selectbox("Type", ["Auto-detect", "IP", "Domain", "URL", "Hash (MD5/SHA1/SHA256)", "CVE"])

    with st.expander("What can I look up?"):
        st.markdown("""
        | Type | Example | What it checks |
        |---|---|---|
        | **IP Address** | `81.19.219.221` | Whether this server is known for abuse or malware |
        | **Domain** | `evil-phishing.xyz` | Reputation + when it was registered |
        | **URL / Link** | `https://fake-login.com/steal` | Whether the link is flagged as malicious |
        | **File Hash** | `a3f1c2d4...` | Whether this file is known malware |
        | **CVE** | `CVE-2021-44228` | Details on a known software vulnerability |
        """)

    if st.button("Check", type="primary") and ioc_input:
        with st.spinner("Checking threat intelligence databases..."):
            result = asyncio.run(_single_lookup(ioc_input, ioc_type))
        st.markdown("---")
        _render_ioc_lookup(result)


# ── Alert Triage ──────────────────────────────────────────────────────────────
elif page == "Alert Triage":
    st.markdown('<div class="page-header"><h1>Alert Triage</h1><p>Paste a SIEM alert or log entry to extract indicators, score risk, and get recommended actions.</p></div>', unsafe_allow_html=True)
    st.markdown("---")

    log_input = st.text_area("Alert or log content", height=250,
        placeholder="Paste a SIEM alert, Windows Event Log, firewall log, or any security alert here...")

    if st.button("Triage", type="primary") and log_input:
        bar  = st.progress(0, text="Starting triage...")
        info = st.empty()

        info.caption("Parsing alert and extracting indicators...")
        bar.progress(10, text="Parsing alert...")
        parsed = parse_log(log_input)

        info.caption("Checking indicators against threat intelligence databases...")
        bar.progress(25, text="Running threat intelligence lookups...")
        enrichment = asyncio.run(_enrich(parsed))
        parsed.update(enrichment)

        info.caption("Mapping to MITRE ATT&CK framework...")
        bar.progress(60, text="Mapping attack techniques...")
        techniques = map_techniques(parsed)
        parsed["mitre_techniques"] = techniques

        info.caption("Calculating risk score...")
        bar.progress(70, text="Scoring...")
        score_result = score(parsed)
        parsed["score"] = score_result

        info.caption("Generating AI triage report. Usually 30 to 90 seconds...")
        bar.progress(75, text="Generating AI report — please wait...")
        report = generate_report(parsed)

        bar.progress(100, text="Triage complete.")
        info.empty()
        bar.empty()

        st.markdown("---")
        _render_score(score_result)
        st.markdown("---")
        col_l, col_r = st.columns(2)
        with col_l:
            _render_breakdown(score_result)
        with col_r:
            _render_mitre(techniques)
        st.markdown("---")
        _render_iocs(parsed)
        st.markdown("---")
        _render_enrichment(parsed)
        st.markdown("---")
        _render_report(report)
        st.markdown("---")
        _save_report(parsed, score_result, techniques, report)

    elif not log_input:
        st.info("Paste an alert above and click Triage.")


# ── Reports ───────────────────────────────────────────────────────────────────
elif page == "Reports":
    st.markdown('<div class="page-header"><h1>Saved Reports</h1><p>Every analysis is automatically saved here as a Markdown file you can download or export as PDF.</p></div>', unsafe_allow_html=True)
    st.markdown("---")

    reports = sorted(REPORTS_DIR.glob("*.md"), reverse=True)
    if not reports:
        st.info("No reports yet. Run an analysis on the Email Analyzer or Alert Triage page to generate one.")
    else:
        st.caption(f"{len(reports)} report(s) saved")
        for r in reports:
            mtime = datetime.fromtimestamp(r.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            with st.expander(f"{r.stem}  ·  {mtime}"):
                st.markdown(r.read_text())
                with open(r, "rb") as f:
                    st.download_button("Download .md", f, file_name=r.name, key=r.name)


# ── Settings ──────────────────────────────────────────────────────────────────
elif page == "Settings":
    st.markdown('<div class="page-header"><h1>Settings</h1><p>Edit the .env file in your project folder and restart the app to apply changes.</p></div>', unsafe_allow_html=True)
    st.markdown("---")
    st.info("To change settings, open the `.env` file in your project folder and restart the app.")

    col1, col2 = st.columns(2)
    with col1:
        st.metric("AI Model", config.OLLAMA_MODEL)
        st.metric("VirusTotal Rate Limit", f"{config.VT_CALLS_PER_MINUTE} lookups/minute (free tier)")
    with col2:
        st.metric("Ollama URL", config.OLLAMA_BASE_URL)
        st.metric("AbuseIPDB Daily Limit", f"{config.ABUSEIPDB_DAILY_LIMIT} lookups/day (free tier)")

    st.markdown("---")
    st.subheader("Test Ollama Connection")
    st.markdown("Ollama runs the AI locally on your machine. Click below to confirm it's running.")
    if st.button("Test Connection", type="primary"):
        import ollama as _ollama
        try:
            models = _ollama.list()
            names = [m.get("name", m.get("model", "")) for m in models.get("models", [])]
            st.success(f"✅ Ollama is running. Models available: {', '.join(names) or 'none pulled yet — run: ollama pull llama3.1:8b'}")
        except Exception as e:
            st.error(f"❌ Cannot reach Ollama: {e}\n\nFix: open a terminal and run `ollama serve`")
