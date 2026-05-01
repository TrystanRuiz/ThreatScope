import re
from app.utils.defang import defang_url, defang_domain, defang_ip

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|co|ru|cn|info|biz|xyz|top|club|online|site|tech|gov|edu|mil|int|arpa)\b", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

def extract_urls(text: str) -> list[dict]:
    return [{"value": m, "defanged": defang_url(m)} for m in set(_URL.findall(text))]

def extract_domains(text: str) -> list[dict]:
    urls = set(_URL.findall(text))
    url_domains = set()
    for u in urls:
        m = re.search(r"https?://([^/\s]+)", u)
        if m:
            url_domains.add(m.group(1))
    domains = set(_DOMAIN.findall(text)) - url_domains
    return [{"value": d, "defanged": defang_domain(d)} for d in domains]

def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)

def extract_ipv4(text: str) -> list[dict]:
    private = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)")
    ips = [ip for ip in set(_IP.findall(text)) if _valid_ip(ip) and not private.match(ip)]
    return [{"value": ip, "defanged": defang_ip(ip)} for ip in ips]

def extract_hashes(text: str) -> list[dict]:
    results = []
    for h in set(_SHA256.findall(text)):
        results.append({"value": h, "type": "sha256"})
    remaining = text
    for h in set(_SHA1.findall(text)):
        if h not in [r["value"] for r in results]:
            results.append({"value": h, "type": "sha1"})
    for h in set(_MD5.findall(text)):
        if h not in [r["value"] for r in results]:
            results.append({"value": h, "type": "md5"})
    return results

def extract_cves(text: str) -> list[str]:
    return list(set(_CVE.findall(text)))

def extract_emails(text: str) -> list[str]:
    return list(set(_EMAIL.findall(text)))

def extract_all_iocs(text: str) -> dict:
    return {
        "urls": extract_urls(text),
        "domains": extract_domains(text),
        "ips": extract_ipv4(text),
        "hashes": extract_hashes(text),
        "cves": extract_cves(text),
        "emails": extract_emails(text),
    }
