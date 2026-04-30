import re

RULES = [
    {
        "id": "T1566",
        "name": "Phishing",
        "check": lambda e: bool(e.get("sender_mismatch") or (e.get("iocs", {}).get("urls") and e.get("urgency_phrases"))),
    },
    {
        "id": "T1204",
        "name": "User Execution",
        "check": lambda e: any(
            re.search(r"\.(exe|js|vbs|bat|ps1|hta|docm|xlsm)$", a, re.IGNORECASE)
            for a in e.get("attachments", [])
        ),
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "check": lambda e: bool(re.search(r"powershell|cmd\.exe|wscript|cscript", str(e.get("suspicious_keywords", "")), re.IGNORECASE)),
    },
    {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "check": lambda e: bool(re.search(r"registry|autorun|startup|hkcu|hklm", str(e.get("raw_preview", "")), re.IGNORECASE)),
    },
    {
        "id": "T1056",
        "name": "Input Capture",
        "check": lambda e: bool(re.search(r"credential|login|password|harvest", str(e.get("subject", "")) + str(e.get("body_preview", "")), re.IGNORECASE)),
    },
    {
        "id": "T1583",
        "name": "Acquire Infrastructure",
        "check": lambda e: any(w.get("newly_registered") for w in e.get("whois_results", [])),
    },
    {
        "id": "T1036",
        "name": "Masquerading",
        "check": lambda e: bool(e.get("sender_mismatch") and e.get("urgency_phrases")),
    },
]

def map_techniques(evidence: dict) -> list[dict]:
    matched = []
    for rule in RULES:
        try:
            if rule["check"](evidence):
                matched.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "confidence": "medium",
                    "url": f"https://attack.mitre.org/techniques/{rule['id']}/",
                })
        except Exception:
            pass
    return matched
