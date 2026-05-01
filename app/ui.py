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
.block-container { max-width: 1100px; padding-top: 2rem; padding-bottom: 3rem; }

/* ── Page header ── */
.page-header { margin-bottom: 6px; }
.page-header h1 { font-size: 28px; font-weight: 700; color: #f0f0f0; margin: 0; }
.page-header p  { font-size: 14px; color: #777; margin: 4px 0 0 0; }

/* ── Cards ── */
.card {
    background: #1a1d2e;
    border-radius: 10px;
    padding: 18px 22px;
    margin-bottom: 10px;
    border-left: 4px solid #2a2d3e;
    transition: border-left-color 0.2s;
}
.card.critical { border-left-color: #ff4b4b; }
.card.high     { border-left-color: #ff8c00; }
.card.medium   { border-left-color: #ffd700; }
.card.low      { border-left-color: #21c55d; }
.card.clean    { border-left-color: #21c55d; }
.card.info     { border-left-color: #3b82f6; }

/* ── Typography ── */
.label { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 1.2px; margin-bottom: 6px; }
.big   { font-size: 38px; font-weight: 800; line-height: 1; }
.plain { font-size: 14px; color: #bbb; line-height: 1.65; margin-top: 6px; }
.sub   { font-size: 12px; color: #666; margin-top: 2px; }
.mono  { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; }

/* ── Badges ── */
.badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; margin: 2px; letter-spacing: 0.3px; }
.b-red { background: #ff4b4b18; color: #ff4b4b; border: 1px solid #ff4b4b44; }
.b-ora { background: #ff8c0018; color: #ff8c00; border: 1px solid #ff8c0044; }
.b-yel { background: #ffd70018; color: #ffd700; border: 1px solid #ffd70044; }
.b-grn { background: #21c55d18; color: #21c55d; border: 1px solid #21c55d44; }
.b-blu { background: #3b82f618; color: #3b82f6; border: 1px solid #3b82f644; }
.b-gry { background: #44444418; color: #888;    border: 1px solid #44444444; }

/* ── IOC rows ── */
.ioc-row {
    background: #12141f;
    border-radius: 6px;
    padding: 9px 14px;
    margin: 3px 0;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 13px;
    color: #d0d0d0;
    border: 1px solid #1e2130;
}

/* ── Finding / Action items ── */
.finding { background: #1a1d2e; border-radius: 6px; padding: 10px 16px; margin: 5px 0; border-left: 3px solid #3b82f6; font-size: 14px; color: #ccc; line-height: 1.5; }
.action  { background: #141f19; border-radius: 6px; padding: 10px 16px; margin: 5px 0; border-left: 3px solid #21c55d; font-size: 14px; color: #ccc; line-height: 1.5; }

/* ── Section dividers ── */
.section {
    font-size: 13px;
    font-weight: 600;
    color: #555;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 28px 0 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid #1e2130;
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: #12141f;
    border-right: 1px solid #1e2130;
}
[data-testid="stSidebar"] .stSelectbox label { color: #888; font-size: 12px; }

/* ── Buttons ── */
.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    font-size: 14px;
    padding: 8px 20px;
    transition: opacity 0.15s;
}
.stButton > button:hover { opacity: 0.85; }

/* ── Inputs ── */
.stTextArea textarea, .stTextInput input {
    background: #12141f;
    border: 1px solid #2a2d3e;
    border-radius: 8px;
    color: #e0e0e0;
    font-size: 14px;
}

/* ── Divider ── */
hr { border-color: #1e2130; margin: 20px 0; }

/* ── Status box ── */
[data-testid="stStatus"] { border-radius: 8px; }

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: #1a1d2e;
    border-radius: 10px;
    padding: 14px 18px;
    border: 1px solid #1e2130;
}
</style>
""", unsafe_allow_html=True)


# ── Plain-language helpers ────────────────────────────────────────────────────

MITRE_PLAIN = {
    "T1566": "Attackers sent a deceptive message designed to trick the recipient into clicking a link or opening a file.",
    "T1204": "The email contains an attachment that requires the user to open or run it — a common way to install malware.",
    "T1059": "Evidence of scripting tools (like PowerShell) that attackers use to run commands and take control of a system.",
    "T1547": "Attackers may be attempting to keep malware running every time the computer starts up.",
    "T1056": "This looks like a credential harvesting attempt — designed to steal your username and password.",
    "T1583": "The domain or infrastructure used was newly set up, which is common when attackers prepare for a campaign.",
    "T1036": "The sender is disguising themselves as a trusted source to gain the recipient's trust.",
}

SIGNAL_PLAIN = {
    "sender_mismatch":        "The 'From' address and 'Reply-To' address belong to different domains — a classic phishing trick.",
    "newly_registered_domain":"The domain was registered very recently. Attackers often register new domains right before launching a campaign.",
    "suspicious_url":         "A suspicious link was found in the content.",
    "vt_detections_3plus":    "Multiple cybersecurity companies flagged this as malicious.",
    "abuseipdb_score_50plus": "This IP address has been widely reported for malicious activity.",
    "urgency_language":       "The message uses high-pressure language to rush the recipient into acting without thinking.",
    "attachment_present":     "An attachment was found. Malicious files are commonly delivered as email attachments.",
    "cve_cvss_7plus":         "A known critical vulnerability was referenced — attackers sometimes exploit these.",
    "mitre_technique_mapped": "Known attacker techniques were identified in this content.",
    "spf_dkim_dmarc_fail":    "Email authentication checks failed — this email did not come from a legitimate server.",
}

LEVEL_ADVICE = {
    "Critical": "This content shows strong evidence of malicious activity. Do not click any links, open any attachments, or reply. Escalate to your security team immediately.",
    "High":     "Multiple threat indicators were found. Treat this as likely malicious. Do not interact with any links or attachments. Report it.",
    "Medium":   "Some suspicious patterns were detected. Proceed with caution. Do not click links unless you can independently verify the sender.",
    "Low":      "Few or no threat indicators found. This appears relatively safe, but always verify unexpected emails with the sender directly.",
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
    s = score_result["score"]
    level = score_result["level"]
    cls = _cls(level)
    col = _col(s)
    advice = LEVEL_ADVICE[level]

    st.markdown(f"""
    <div class="card {cls}" style="display:flex;gap:30px;align-items:flex-start;flex-wrap:wrap;">
        <div>
            <div class="label">Overall Risk Score</div>
            <div class="big" style="color:{col};">{s}<span style="font-size:18px;color:#555;">/100</span></div>
            <div style="font-size:20px;font-weight:700;color:{col};margin-top:4px;">{level} Risk</div>
        </div>
        <div style="flex:1;min-width:200px;border-left:1px solid #333;padding-left:20px;">
            <div class="label">What this means</div>
            <div class="plain">{advice}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def _render_breakdown(score_result: dict):
    st.markdown('<div class="section">How the score was calculated</div>', unsafe_allow_html=True)
    st.markdown('<div class="plain" style="margin-bottom:12px;">Each item below contributed points to the overall risk score. Green items were not triggered.</div>', unsafe_allow_html=True)
    for signal, pts in score_result["breakdown"].items():
        plain = SIGNAL_PLAIN.get(signal, signal.replace("_"," ").title())
        if pts > 0:
            st.markdown(f"""
            <div class="card high" style="padding:10px 16px;display:flex;justify-content:space-between;align-items:center;gap:10px;">
                <div>
                    <div style="font-weight:600;font-size:14px;">⚠️ {signal.replace('_',' ').title()}</div>
                    <div class="plain" style="margin-top:2px;">{plain}</div>
                </div>
                <div style="font-size:22px;font-weight:800;color:#ff8c00;min-width:48px;text-align:right;">+{pts}</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="card" style="padding:8px 16px;display:flex;justify-content:space-between;align-items:center;opacity:0.35;">
                <div style="font-size:13px;">✅ {signal.replace('_',' ').title()}</div>
                <div style="font-size:14px;color:#555;">+0</div>
            </div>
            """, unsafe_allow_html=True)


def _render_mitre(techniques: list):
    st.markdown('<div class="section">Attack Techniques Identified</div>', unsafe_allow_html=True)
    if not techniques:
        st.markdown('<div class="card" style="opacity:0.5;"><div class="plain">No known attack techniques were matched in this content.</div></div>', unsafe_allow_html=True)
        return
    st.markdown('<div class="plain" style="margin-bottom:10px;">These are techniques from the MITRE ATT&CK framework — a globally recognized catalog of how real attackers operate. Finding these doesn\'t confirm an attack, but they are serious signals to investigate.</div>', unsafe_allow_html=True)
    for t in techniques:
        plain = MITRE_PLAIN.get(t["id"], "A known attacker technique was detected.")
        st.markdown(f"""
        <div class="card medium" style="padding:12px 16px;">
            <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                <div>
                    <span class="mono" style="color:#ffd700;font-weight:700;">{t['id']}</span>
                    <span style="color:#e0e0e0;margin-left:10px;font-weight:600;">{t['name']}</span>
                </div>
                <span class="badge {'b-red' if t['confidence']=='high' else 'b-yel' if t['confidence']=='medium' else 'b-gry'}">{t['confidence'].capitalize()} confidence</span>
            </div>
            <div class="plain" style="margin-top:6px;">{plain}</div>
            <div style="margin-top:6px;"><a href="{t['url']}" target="_blank" style="font-size:12px;color:#3b82f6;">View full technique details on MITRE ATT&CK →</a></div>
        </div>
        """, unsafe_allow_html=True)


def _render_iocs(parsed: dict):
    st.markdown('<div class="section">Indicators of Compromise (IOCs)</div>', unsafe_allow_html=True)
    st.markdown('<div class="plain" style="margin-bottom:10px;">These are the suspicious items extracted from the content. URLs and domains are shown in defanged format (with brackets) so they cannot be accidentally clicked.</div>', unsafe_allow_html=True)

    iocs = parsed.get("iocs", {})
    type_labels = {
        "urls": "Links / URLs",
        "domains": "Domains",
        "ips": "IP Addresses",
        "hashes": "File Hashes",
        "cves": "Known Vulnerabilities (CVEs)",
        "emails": "Email Addresses",
    }
    any_found = False
    for key, label in type_labels.items():
        items = iocs.get(key, [])
        if not items:
            continue
        any_found = True
        st.markdown(f'<div style="font-size:13px;color:#aaa;margin:8px 0 4px;">{label}</div>', unsafe_allow_html=True)
        for item in items:
            val = item.get("defanged", item.get("value", item)) if isinstance(item, dict) else item
            st.markdown(f'<div class="ioc-row">{val}</div>', unsafe_allow_html=True)

    if not any_found:
        st.markdown('<div class="card" style="opacity:0.5;"><div class="plain">No indicators were extracted from this content.</div></div>', unsafe_allow_html=True)

    attachments = parsed.get("attachments", [])
    if attachments:
        st.markdown('<div style="font-size:13px;color:#aaa;margin:8px 0 4px;">Attachments</div>', unsafe_allow_html=True)
        for a in attachments:
            danger = any(a.lower().endswith(ext) for ext in [".exe",".js",".vbs",".bat",".ps1",".hta",".docm",".xlsm",".zip",".rar"])
            st.markdown(f'<div class="ioc-row" style="color:{"#ff4b4b" if danger else "#e0e0e0"};">{"⚠️ " if danger else ""}{a}{"  — Dangerous file type" if danger else ""}</div>', unsafe_allow_html=True)


def _render_enrichment(parsed: dict):
    st.markdown('<div class="section">Threat Intelligence Results</div>', unsafe_allow_html=True)
    st.markdown('<div class="plain" style="margin-bottom:10px;">These results come from real-time lookups against threat intelligence databases. They help determine whether the identified indicators are known to be malicious.</div>', unsafe_allow_html=True)

    vt  = [r for r in parsed.get("vt_results", [])    if not r.get("skipped")]
    ab  = [r for r in parsed.get("abuse_results", []) if not r.get("skipped")]
    wh  = parsed.get("whois_results", [])
    nv  = [r for r in parsed.get("nvd_results", [])   if not r.get("skipped")]
    mb  = [r for r in parsed.get("mb_results", [])    if not r.get("skipped")]
    skipped = [r for r in parsed.get("vt_results", []) + parsed.get("abuse_results", []) + parsed.get("nvd_results", []) + parsed.get("mb_results", []) if r.get("skipped")]

    if not any([vt, ab, wh, nv, mb]):
        st.markdown('<div class="card info"><div class="plain">No threat intelligence results were returned. This could mean the indicators are unknown, or enrichment was skipped (offline mode or missing API keys).</div></div>', unsafe_allow_html=True)

    for r in vt:
        mal = r.get("malicious", 0)
        sus = r.get("suspicious", 0)
        har = r.get("harmless", 0)
        total = mal + sus + har
        cls = "critical" if mal >= 5 else "high" if mal >= 3 else "medium" if mal >= 1 else "clean"
        if mal >= 5:
            verdict = "Highly malicious — flagged by many security vendors."
            verdict_col = "#ff4b4b"
        elif mal >= 3:
            verdict = "Likely malicious — flagged by multiple security vendors."
            verdict_col = "#ff8c00"
        elif mal >= 1:
            verdict = "Possibly suspicious — flagged by at least one vendor. Investigate further."
            verdict_col = "#ffd700"
        else:
            verdict = "No vendors flagged this as malicious. Appears clean."
            verdict_col = "#21c55d"
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">VirusTotal — {r.get('ioc','')}</div>
            <div style="display:flex;gap:24px;margin:10px 0;flex-wrap:wrap;">
                <div><div class="sub">Flagged malicious by</div><div style="font-size:28px;font-weight:800;color:#ff4b4b;">{mal}<span style="font-size:14px;color:#555;"> / {total} vendors</span></div></div>
                <div><div class="sub">Suspicious</div><div style="font-size:22px;font-weight:700;color:#ff8c00;">{sus}</div></div>
                <div><div class="sub">Clean</div><div style="font-size:22px;font-weight:700;color:#21c55d;">{har}</div></div>
            </div>
            <div style="color:{verdict_col};font-size:14px;font-weight:600;">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    for r in ab:
        conf = r.get("abuse_confidence", 0)
        reports = r.get("total_reports", 0)
        cls = "critical" if conf >= 75 else "high" if conf >= 50 else "medium" if conf >= 25 else "clean"
        if conf >= 75:
            verdict = f"This IP is widely known as malicious — {reports} separate abuse reports on record."
        elif conf >= 50:
            verdict = f"This IP has a high abuse score and has been reported {reports} times."
        elif conf >= 25:
            verdict = f"Some abuse reports exist for this IP ({reports} total). Treat with caution."
        else:
            verdict = f"Low abuse score. Only {reports} reports on record. Appears relatively safe."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">AbuseIPDB — IP Reputation — {r.get('ioc','')}</div>
            <div style="display:flex;gap:30px;margin:10px 0;align-items:center;flex-wrap:wrap;">
                <div>
                    <div class="sub">Abuse Confidence Score</div>
                    <div class="big" style="color:{'#ff4b4b' if conf>=75 else '#ff8c00' if conf>=50 else '#ffd700' if conf>=25 else '#21c55d'};">{conf}%</div>
                </div>
                <div><div class="sub">Country</div><div style="font-size:16px;font-weight:600;">{r.get('country','?')}</div></div>
                <div><div class="sub">ISP / Hosting</div><div style="font-size:14px;">{r.get('isp','unknown')}</div></div>
                <div><div class="sub">Total Reports</div><div style="font-size:22px;font-weight:700;">{reports}</div></div>
            </div>
            <div style="font-size:14px;font-weight:600;color:{'#ff4b4b' if conf>=75 else '#ff8c00' if conf>=50 else '#aaa'};">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    for r in wh:
        age = r.get("age_days")
        new = r.get("newly_registered", False)
        cls = "high" if new else "low"
        age_str = f"{age} days old" if age is not None else "unknown"
        if new:
            verdict = f"⚠️ This domain was registered only {age} days ago. Newly created domains are a major red flag — attackers set them up just before launching attacks."
        elif age and age < 180:
            verdict = f"This domain is relatively new ({age} days old). Not necessarily malicious, but worth noting."
        else:
            verdict = f"This domain has been around for {age_str}. Older domains are generally more trustworthy."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">WHOIS — Domain Age — {r.get('domain','')}</div>
            <div style="display:flex;gap:30px;margin:10px 0;flex-wrap:wrap;">
                <div><div class="sub">Registrar</div><div style="font-size:14px;">{r.get('registrar','unknown')}</div></div>
                <div><div class="sub">Registered on</div><div style="font-size:14px;">{r.get('creation_date','unknown')}</div></div>
                <div><div class="sub">Domain Age</div><div style="font-size:22px;font-weight:700;color:{'#ff8c00' if new else '#21c55d'};">{age_str}</div></div>
                <div><div class="sub">Country</div><div style="font-size:14px;">{r.get('country','unknown')}</div></div>
            </div>
            <div style="font-size:14px;font-weight:600;color:{'#ff8c00' if new else '#888'};">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    for r in nv:
        cvss = r.get("cvss_score", 0)
        sev = r.get("severity", "unknown").capitalize()
        cls = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
        if cvss >= 9:
            verdict = "Critical severity vulnerability. Systems running unpatched software are at serious risk."
        elif cvss >= 7:
            verdict = "High severity vulnerability. This flaw can be exploited to compromise a system if left unpatched."
        elif cvss >= 4:
            verdict = "Medium severity. Not immediately critical, but should be patched."
        else:
            verdict = "Low severity vulnerability."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">Known Vulnerability — {r.get('ioc','')}</div>
            <div style="display:flex;gap:30px;margin:10px 0;align-items:flex-start;flex-wrap:wrap;">
                <div>
                    <div class="sub">CVSS Severity Score (0–10)</div>
                    <div class="big" style="color:{'#ff4b4b' if cvss>=7 else '#ffd700'};">{cvss}</div>
                    <div style="font-size:14px;color:#aaa;">{sev}</div>
                </div>
                <div style="flex:1;">
                    <div class="sub">What is this vulnerability?</div>
                    <div style="font-size:13px;color:#ccc;margin-top:4px;">{r.get('description','No description available.')}</div>
                </div>
            </div>
            <div style="font-size:14px;font-weight:600;color:{'#ff4b4b' if cvss>=7 else '#aaa'};">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    for r in mb:
        found = r.get("found", False)
        cls = "critical" if found else "clean"
        tags = ", ".join(r.get("tags", [])) or "none"
        if found:
            verdict = f"This file is in the MalwareBazaar database — classified as {r.get('signature','unknown')}. First seen {r.get('first_seen','?')}."
        else:
            verdict = "This file hash was not found in MalwareBazaar. It may be clean or simply not yet cataloged."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">MalwareBazaar — File Hash — {r.get('ioc','')[:32]}...</div>
            <div style="display:flex;gap:24px;margin:10px 0;flex-wrap:wrap;">
                <div><div class="sub">Known Malware</div><div style="font-size:22px;font-weight:700;color:{'#ff4b4b' if found else '#21c55d'};">{'YES' if found else 'NOT FOUND'}</div></div>
                {"<div><div class='sub'>File Name</div><div style='font-size:13px;'>" + r.get('file_name','?') + "</div></div>" if found else ""}
                {"<div><div class='sub'>Malware Family</div><div style='font-size:13px;'>" + r.get('signature','?') + "</div></div>" if found else ""}
                {"<div><div class='sub'>File Type</div><div style='font-size:13px;'>" + r.get('file_type','?') + "</div></div>" if found else ""}
                {"<div><div class='sub'>Tags</div><div style='font-size:13px;'>" + tags + "</div></div>" if found else ""}
            </div>
            <div style="font-size:14px;font-weight:600;color:{'#ff4b4b' if found else '#888'};">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    if skipped:
        with st.expander(f"{len(skipped)} lookup(s) skipped"):
            for r in skipped:
                st.caption(f"• {r.get('ioc','')} — {r.get('source','')} — {r.get('reason','')}")


def _render_report(report: dict):
    st.markdown('<div class="section">Investigation Report</div>', unsafe_allow_html=True)
    summary = report.get("executive_summary", "")
    if summary:
        st.markdown(f'<div class="card info"><div class="label">Summary</div><div class="plain" style="margin-top:6px;">{summary}</div></div>', unsafe_allow_html=True)

    findings = report.get("technical_findings", [])
    if findings:
        st.markdown('<div style="font-size:13px;color:#aaa;margin:10px 0 4px;">Technical Findings</div>', unsafe_allow_html=True)
        for f in findings:
            st.markdown(f'<div class="finding">🔍 {f}</div>', unsafe_allow_html=True)

    actions = report.get("recommended_actions", [])
    if actions:
        st.markdown('<div style="font-size:13px;color:#aaa;margin:10px 0 4px;">Recommended Actions</div>', unsafe_allow_html=True)
        for a in actions:
            st.markdown(f'<div class="action">✅ {a}</div>', unsafe_allow_html=True)

    notes = report.get("analyst_notes", "")
    if notes:
        st.markdown(f'<div class="card" style="margin-top:10px;opacity:0.7;"><div class="label">Analyst Notes</div><div class="plain">{notes}</div></div>', unsafe_allow_html=True)


def _render_ioc_lookup(result: dict):
    ioc_type = result.get("type", "unknown")

    if result.get("error"):
        st.error(result["error"])
        return

    vt = result.get("vt", {})
    if vt and not vt.get("skipped"):
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        har = vt.get("harmless", 0)
        total = mal + sus + har
        cls = "critical" if mal >= 5 else "high" if mal >= 3 else "medium" if mal >= 1 else "clean"
        if mal >= 5:    verdict = "This is highly dangerous. Avoid any contact with this indicator."
        elif mal >= 3:  verdict = "Multiple security vendors flagged this. Likely malicious."
        elif mal >= 1:  verdict = "At least one vendor flagged this. Investigate before trusting it."
        else:           verdict = "No vendors flagged this. It appears clean, but this doesn't guarantee safety."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">VirusTotal Security Scan</div>
            <div class="plain" style="margin-bottom:10px;">VirusTotal checks an indicator against 70+ antivirus and security companies simultaneously.</div>
            <div style="display:flex;gap:30px;flex-wrap:wrap;margin-bottom:12px;">
                <div><div class="sub">Flagged as malicious by</div><div style="font-size:36px;font-weight:800;color:#ff4b4b;">{mal}<span style="font-size:16px;color:#555;"> of {total} vendors</span></div></div>
                <div><div class="sub">Suspicious</div><div style="font-size:26px;font-weight:700;color:#ff8c00;">{sus}</div></div>
                <div><div class="sub">Clean / Safe</div><div style="font-size:26px;font-weight:700;color:#21c55d;">{har}</div></div>
            </div>
            <div style="font-size:15px;font-weight:700;color:{'#ff4b4b' if mal>=3 else '#ffd700' if mal>=1 else '#21c55d'};">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)
    elif vt and vt.get("skipped"):
        st.markdown(f'<div class="card info"><div class="label">VirusTotal</div><div class="plain">Lookup skipped: {vt.get("reason","")}</div></div>', unsafe_allow_html=True)

    ab = result.get("abuseipdb", {})
    if ab and not ab.get("skipped"):
        conf = ab.get("abuse_confidence", 0)
        reports = ab.get("total_reports", 0)
        cls = "critical" if conf >= 75 else "high" if conf >= 50 else "medium" if conf >= 25 else "clean"
        if conf >= 75:  verdict = f"This IP is widely known as malicious. It has been reported {reports} times by the security community. Block it."
        elif conf >= 50:verdict = f"High abuse score. Reported {reports} times. Treat as malicious unless proven otherwise."
        elif conf >= 25:verdict = f"Some reports exist ({reports} total). Approach with caution."
        else:           verdict = f"Low abuse history ({reports} reports). The IP appears relatively safe."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">AbuseIPDB — IP Reputation Check</div>
            <div class="plain" style="margin-bottom:10px;">AbuseIPDB is a community-driven database where security researchers report malicious IP addresses.</div>
            <div style="display:flex;gap:30px;flex-wrap:wrap;margin-bottom:12px;">
                <div>
                    <div class="sub">Abuse Confidence Score</div>
                    <div style="font-size:48px;font-weight:800;color:{'#ff4b4b' if conf>=75 else '#ff8c00' if conf>=50 else '#ffd700' if conf>=25 else '#21c55d'};">{conf}%</div>
                    <div class="sub">0% = clean, 100% = confirmed malicious</div>
                </div>
                <div style="border-left:1px solid #333;padding-left:24px;">
                    <div style="margin-bottom:10px;"><div class="sub">Total Abuse Reports</div><div style="font-size:22px;font-weight:700;">{reports}</div></div>
                    <div style="margin-bottom:10px;"><div class="sub">ISP / Provider</div><div style="font-size:14px;">{ab.get('isp','unknown')}</div></div>
                    <div style="margin-bottom:10px;"><div class="sub">Country</div><div style="font-size:14px;">{ab.get('country','unknown')}</div></div>
                    <div><div class="sub">Whitelisted</div><div style="font-size:14px;">{"Yes" if ab.get('is_whitelisted') else "No"}</div></div>
                </div>
            </div>
            <div style="font-size:15px;font-weight:700;color:{'#ff4b4b' if conf>=75 else '#ff8c00' if conf>=50 else '#aaa'};">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    wh = result.get("whois", {})
    if wh:
        age = wh.get("age_days")
        new = wh.get("newly_registered", False)
        age_str = f"{age} days" if age is not None else "unknown"
        if new:         verdict = f"⚠️ Registered only {age} days ago — very suspicious. Fresh domains are a hallmark of phishing campaigns."
        elif age and age < 180: verdict = f"Relatively new domain ({age} days). Worth noting but not automatically malicious."
        else:           verdict = "This is an established domain. Older domains are generally more trustworthy."
        st.markdown(f"""
        <div class="card {'high' if new else 'low'}">
            <div class="label">WHOIS — Domain Registration Info</div>
            <div class="plain" style="margin-bottom:10px;">WHOIS records show when a domain was registered. Attackers often create new domains right before launching an attack.</div>
            <div style="display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px;">
                <div><div class="sub">Domain Age</div><div style="font-size:28px;font-weight:800;color:{'#ff8c00' if new else '#21c55d'};">{age_str}</div></div>
                <div><div class="sub">Registered On</div><div style="font-size:14px;">{wh.get('creation_date','unknown')}</div></div>
                <div><div class="sub">Registrar</div><div style="font-size:14px;">{wh.get('registrar','unknown')}</div></div>
                <div><div class="sub">Country</div><div style="font-size:14px;">{wh.get('country','unknown')}</div></div>
            </div>
            <div style="font-size:15px;font-weight:700;color:{'#ff8c00' if new else '#888'};">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)

    nvd_r = result.get("nvd", {})
    if nvd_r and not nvd_r.get("skipped"):
        cvss = nvd_r.get("cvss_score", 0)
        sev = nvd_r.get("severity", "?").capitalize()
        cls = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
        if cvss >= 9:   verdict = "Critical vulnerability. Any unpatched system is at serious risk. Patch immediately."
        elif cvss >= 7: verdict = "High severity. This flaw can be actively exploited. Patching is urgent."
        elif cvss >= 4: verdict = "Medium severity. Should be patched but not an immediate emergency."
        else:           verdict = "Low severity vulnerability."
        st.markdown(f"""
        <div class="card {cls}">
            <div class="label">NVD — Known Vulnerability Database</div>
            <div class="plain" style="margin-bottom:10px;">The National Vulnerability Database (NVD) tracks publicly known security flaws in software. Each one gets a score from 0–10 based on how dangerous it is.</div>
            <div style="display:flex;gap:30px;flex-wrap:wrap;margin-bottom:12px;align-items:flex-start;">
                <div>
                    <div class="sub">Danger Score (CVSS)</div>
                    <div style="font-size:48px;font-weight:800;color:{'#ff4b4b' if cvss>=7 else '#ffd700' if cvss>=4 else '#21c55d'};">{cvss}</div>
                    <div class="sub">out of 10 — {sev}</div>
                </div>
                <div style="flex:1;border-left:1px solid #333;padding-left:24px;">
                    <div class="sub">What is this vulnerability?</div>
                    <div style="font-size:13px;color:#ccc;margin-top:6px;line-height:1.6;">{nvd_r.get('description','No description available.')}</div>
                </div>
            </div>
            <div style="font-size:15px;font-weight:700;color:{'#ff4b4b' if cvss>=7 else '#aaa'};">→ {verdict}</div>
        </div>
        """, unsafe_allow_html=True)
    elif nvd_r and nvd_r.get("skipped"):
        st.markdown(f'<div class="card info"><div class="label">NVD</div><div class="plain">Lookup skipped: {nvd_r.get("reason","")}</div></div>', unsafe_allow_html=True)


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
        if val == "pass":   return f'<span class="badge b-grn">✅ {name}: PASS</span>'
        if val == "fail":   return f'<span class="badge b-red">❌ {name}: FAIL</span>'
        return f'<span class="badge b-gry">❓ {name}: {val.upper()}</span>'

    auth_html = _auth_badge("SPF", spf) + _auth_badge("DKIM", dkim) + _auth_badge("DMARC", dmarc)
    mismatch = parsed.get("sender_mismatch", False)

    st.markdown(f"""
    <div class="card {'critical' if (spf=='fail' and dkim=='fail') else 'medium' if (spf=='fail' or dkim=='fail') else 'clean'}">
        <div class="label">Authentication Results</div>
        <div style="margin:10px 0;">{auth_html}</div>
        <div class="plain">
            {'⚠️ All three authentication checks failed — this email almost certainly did not come from a legitimate server.' if spf=='fail' and dkim=='fail' and dmarc=='fail'
             else '⚠️ One or more authentication checks failed — treat this email with suspicion.' if 'fail' in [spf,dkim,dmarc]
             else '✅ Authentication checks passed.'}
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

    # Initialize session state for email content
    if "email_content" not in st.session_state:
        st.session_state["email_content"] = ""

    input_method = st.radio("Input method", ["Paste raw email", "Upload .eml file"], horizontal=True)

    col1, col2, col3 = st.columns([2, 2, 6])
    with col1:
        analyze = st.button("Analyze", type="primary", use_container_width=True)
    with col2:
        if st.button("Load Sample", use_container_width=True):
            if SAMPLE_PATH.exists():
                st.session_state["email_content"] = SAMPLE_PATH.read_text()
                st.rerun()
            else:
                st.error("Sample file not found.")

    if input_method == "Paste raw email":
        raw_email = st.text_area(
            "Email content",
            value=st.session_state["email_content"],
            height=250,
            placeholder="Paste the full email here, including headers if available...",
            key="email_text_area",
        )
        st.session_state["email_content"] = raw_email
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
