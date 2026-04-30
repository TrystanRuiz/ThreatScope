import re
from app.parsers.ioc_extractor import extract_all_iocs

SUSPICIOUS_KEYWORDS = re.compile(
    r"\b(powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|net user|net localgroup|whoami|mimikatz|lsass|pass the hash|lateral movement|privilege escalation|reverse shell|beacon|cobalt strike)\b",
    re.IGNORECASE,
)

def parse_log(text: str) -> dict:
    iocs = extract_all_iocs(text)
    keyword_hits = list(set(SUSPICIOUS_KEYWORDS.findall(text)))
    lines = [l.strip() for l in text.splitlines() if l.strip()]

    timestamps = re.findall(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", text)
    event_ids = re.findall(r"EventID[:\s]+(\d+)", text, re.IGNORECASE)

    return {
        "line_count": len(lines),
        "timestamps": timestamps[:10],
        "event_ids": list(set(event_ids)),
        "suspicious_keywords": keyword_hits,
        "iocs": iocs,
        "raw_preview": text[:1000],
    }
