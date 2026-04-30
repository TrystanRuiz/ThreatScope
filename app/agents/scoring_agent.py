from app.utils.logger import get_logger

log = get_logger(__name__)

SIGNALS = {
    "sender_mismatch": 15,
    "newly_registered_domain": 20,
    "suspicious_url": 15,
    "vt_detections_3plus": 25,
    "abuseipdb_score_50plus": 20,
    "urgency_language": 10,
    "attachment_present": 10,
    "cve_cvss_7plus": 20,
    "mitre_technique_mapped": 10,
    "spf_dkim_dmarc_fail": 15,
}

LEVELS = [
    (76, "Critical"),
    (51, "High"),
    (26, "Medium"),
    (0,  "Low"),
]

def score(evidence: dict) -> dict:
    breakdown = {}

    breakdown["sender_mismatch"] = SIGNALS["sender_mismatch"] if evidence.get("sender_mismatch") else 0
    breakdown["urgency_language"] = SIGNALS["urgency_language"] if evidence.get("urgency_phrases") else 0
    breakdown["attachment_present"] = SIGNALS["attachment_present"] if evidence.get("attachments") else 0

    iocs = evidence.get("iocs", {})
    breakdown["suspicious_url"] = SIGNALS["suspicious_url"] if iocs.get("urls") else 0

    # WHOIS signals
    whois_results = evidence.get("whois_results", [])
    breakdown["newly_registered_domain"] = SIGNALS["newly_registered_domain"] if any(
        w.get("newly_registered") for w in whois_results
    ) else 0

    # Auth signals
    auth_fail = any([
        evidence.get("spf") not in ("pass", "unknown", None),
        evidence.get("dkim") not in ("pass", "unknown", None),
        evidence.get("dmarc") not in ("pass", "unknown", None),
    ])
    breakdown["spf_dkim_dmarc_fail"] = SIGNALS["spf_dkim_dmarc_fail"] if auth_fail else 0

    # VT signals
    vt_results = evidence.get("vt_results", [])
    breakdown["vt_detections_3plus"] = SIGNALS["vt_detections_3plus"] if any(
        r.get("malicious", 0) >= 3 for r in vt_results
    ) else 0

    # AbuseIPDB signals
    abuse_results = evidence.get("abuse_results", [])
    breakdown["abuseipdb_score_50plus"] = SIGNALS["abuseipdb_score_50plus"] if any(
        r.get("abuse_confidence", 0) >= 50 for r in abuse_results
    ) else 0

    # CVE signals
    nvd_results = evidence.get("nvd_results", [])
    breakdown["cve_cvss_7plus"] = SIGNALS["cve_cvss_7plus"] if any(
        r.get("cvss_score", 0) >= 7.0 for r in nvd_results
    ) else 0

    # MITRE signals
    breakdown["mitre_technique_mapped"] = SIGNALS["mitre_technique_mapped"] if evidence.get("mitre_techniques") else 0

    total = min(sum(breakdown.values()), 100)
    level = next(label for threshold, label in LEVELS if total >= threshold)

    return {
        "score": total,
        "level": level,
        "breakdown": breakdown,
    }
