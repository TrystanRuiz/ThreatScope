import re

def _text(e: dict) -> str:
    parts = [
        str(e.get("subject", "")),
        str(e.get("body_preview", "")),
        str(e.get("raw_preview", "")),
        str(e.get("suspicious_keywords", "")),
        " ".join(str(a) for a in e.get("attachments", [])),
    ]
    return " ".join(parts).lower()

def _has(pattern: str, e: dict) -> bool:
    return bool(re.search(pattern, _text(e), re.IGNORECASE))

def _ioc_count(e: dict, key: str) -> int:
    return len(e.get("iocs", {}).get(key, []))

RULES = [
    {
        "id": "T1566", "name": "Phishing",
        "signals": [
            lambda e: bool(e.get("sender_mismatch")),
            lambda e: bool(e.get("urgency_phrases")),
            lambda e: _ioc_count(e, "urls") > 0,
            lambda e: e.get("spf") == "fail" or e.get("dkim") == "fail",
        ],
        "threshold": 1,
    },
    {
        "id": "T1204", "name": "User Execution",
        "signals": [
            lambda e: any(re.search(r"\.(exe|js|vbs|bat|ps1|hta|docm|xlsm|jar|msi)$", a, re.IGNORECASE) for a in e.get("attachments", [])),
            lambda e: _has(r"open.*attachment|run.*file|enable.*macro|click.*enable", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1059", "name": "Command and Scripting Interpreter",
        "signals": [
            lambda e: _has(r"powershell|pwsh|cmd\.exe|wscript|cscript|bash|sh -c", e),
            lambda e: _has(r"-encodedcommand|-enc |-nop |-windowstyle hidden", e),
            lambda e: _has(r"invoke-expression|iex\(|invoke-webrequest", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1547", "name": "Boot or Logon Autostart Execution",
        "signals": [
            lambda e: _has(r"hkcu\\software\\microsoft\\windows\\currentversion\\run|hklm\\", e),
            lambda e: _has(r"startup folder|autorun|registry.*persist", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1056", "name": "Input Capture",
        "signals": [
            lambda e: _has(r"credential|password|login|verify.*account|confirm.*details|enter.*information", e),
            lambda e: _ioc_count(e, "urls") > 0 and bool(e.get("sender_mismatch")),
        ],
        "threshold": 1,
    },
    {
        "id": "T1583", "name": "Acquire Infrastructure",
        "signals": [
            lambda e: any(w.get("newly_registered") for w in e.get("whois_results", [])),
            lambda e: _has(r"newly.*registered|fresh.*domain", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1036", "name": "Masquerading",
        "signals": [
            lambda e: bool(e.get("sender_mismatch")),
            lambda e: _has(r"paypal|microsoft|apple|google|amazon|bank|irs|fedex|dhl|support team|security team", e),
            lambda e: bool(e.get("urgency_phrases")),
        ],
        "threshold": 2,
    },
    {
        "id": "T1027", "name": "Obfuscated Files or Information",
        "signals": [
            lambda e: _has(r"base64|[a-zA-Z0-9+/]{50,}={0,2}|char\(|fromcharcode|unescape\(", e),
            lambda e: _has(r"encoded|obfuscat|encrypt.*payload", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1003", "name": "OS Credential Dumping",
        "signals": [
            lambda e: _has(r"mimikatz|lsass|ntds\.dit|secretsdump|procdump.*lsass", e),
            lambda e: _has(r"credential dump|pass the hash|pass the ticket", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1055", "name": "Process Injection",
        "signals": [
            lambda e: _has(r"process inject|shellcode|virtualalloc|writeprocessmemory|createremotethread", e),
            lambda e: _has(r"hollowing|dll inject|reflective", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1486", "name": "Data Encrypted for Impact",
        "signals": [
            lambda e: _has(r"ransomware|your files.*encrypted|bitcoin.*ransom|\.locked|\.encrypted|decrypt.*pay", e),
            lambda e: _has(r"README_DECRYPT|HOW_TO_RESTORE|DECRYPT_INSTRUCTIONS", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1070", "name": "Indicator Removal",
        "signals": [
            lambda e: _has(r"wevtutil.*cl|clear.*eventlog|del.*\.log|remove.*logs|cover.*tracks", e),
            lambda e: _has(r"timestomp|usnjrnl|shadowcopy.*delete|vssadmin.*delete", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1562", "name": "Impair Defenses",
        "signals": [
            lambda e: _has(r"antivirus.*disabled|defender.*off|firewall.*disabled|security.*disabled", e),
            lambda e: _has(r"set-mppreference.*disable|netsh.*firewall.*off|sc.*stop.*mssec", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1021", "name": "Remote Services",
        "signals": [
            lambda e: _has(r"psexec|wmiexec|winrm|rdp|remote desktop|lateral.*move", e),
            lambda e: _has(r"\\\\.*\\admin\$|\\\\.*\\c\$|net use.*\\\\", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1053", "name": "Scheduled Task / Job",
        "signals": [
            lambda e: _has(r"schtasks|at\.exe|crontab|scheduled task|task scheduler", e),
            lambda e: _has(r"/create.*schtasks|new-scheduledtask", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1105", "name": "Ingress Tool Transfer",
        "signals": [
            lambda e: _has(r"certutil.*-decode|certutil.*-urlcache|bitsadmin.*transfer|wget |curl.*-o", e),
            lambda e: _has(r"invoke-webrequest|downloadfile|downloadstring", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1218", "name": "System Binary Proxy Execution",
        "signals": [
            lambda e: _has(r"mshta|regsvr32|rundll32|msiexec|wmic.*process|pcalua", e),
            lambda e: _has(r"scrobj\.dll|ieadvpack\.dll|mshtml\.dll", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1082", "name": "System Information Discovery",
        "signals": [
            lambda e: _has(r"systeminfo|ipconfig|ifconfig|hostname|whoami|net user|net group", e),
            lambda e: _has(r"get-computerinfo|uname -a|cat /etc/os-release", e),
        ],
        "threshold": 1,
    },
    {
        "id": "T1190", "name": "Exploit Public-Facing Application",
        "signals": [
            lambda e: len(e.get("iocs", {}).get("cves", [])) > 0,
            lambda e: any(r.get("cvss_score", 0) >= 7 for r in e.get("nvd_results", [])),
        ],
        "threshold": 1,
    },
    {
        "id": "T1078", "name": "Valid Accounts",
        "signals": [
            lambda e: _has(r"failed login|invalid password|account lockout|brute.?force|credential.*stuff", e),
            lambda e: _has(r"login.*unusual|access.*outside.*hours|impossible travel", e),
        ],
        "threshold": 1,
    },
]

MITRE_URLS = {r["id"]: f"https://attack.mitre.org/techniques/{r['id']}/" for r in RULES}

def map_techniques(evidence: dict) -> list[dict]:
    matched = []
    for rule in RULES:
        try:
            hits = sum(1 for s in rule["signals"] if s(evidence))
            if hits >= rule["threshold"]:
                total = len(rule["signals"])
                if hits >= total:
                    confidence = "high"
                elif hits >= max(1, total // 2):
                    confidence = "medium"
                else:
                    confidence = "low"
                matched.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "confidence": confidence,
                    "signals_matched": hits,
                    "signals_total": total,
                    "url": MITRE_URLS[rule["id"]],
                })
        except Exception:
            pass
    return matched
