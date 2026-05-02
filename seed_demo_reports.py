"""
Run once to populate reports/ with realistic demo data for screenshots.
Usage: python3 seed_demo_reports.py
"""
import random
from pathlib import Path
from datetime import datetime, timedelta

REPORTS_DIR = Path(__file__).parent / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

random.seed(42)

SAMPLES = [
    {
        "subject": "IT Support - Password Reset Required",
        "score": 82, "level": "Critical",
        "summary": "A credential harvesting email impersonating internal IT support was detected. The sender domain does not match corporate infrastructure and the embedded link redirects to an external phishing page.",
        "findings": [
            "Sender domain 'it-support-helpdesk.net' does not match corporate domain",
            "Urgency language: 'Your account will be locked in 24 hours'",
            "Embedded URL redirects to 'login-portal-verify.com'",
            "SPF and DMARC failed for sending domain",
            "VT detections: 12/74 for embedded domain",
            "No attachment, link-only delivery vector",
        ],
        "techniques": [
            ("T1566.002", "Phishing: Spearphishing Link", "Message contains a hyperlink designed to harvest credentials from the recipient."),
            ("T1056.003", "Input Capture: Web Portal Capture", "Linked page mimics a corporate login portal to steal username and password."),
            ("T1036.005", "Masquerading: Match Legitimate Name or Location", "Sender display name matches an internal IT alias while the domain does not."),
        ],
        "actions": [
            "Block domain 'login-portal-verify.com' at the email gateway",
            "Reset credentials for any users who clicked the link",
            "Alert IT Help Desk to send a legitimate advisory to affected users",
        ],
        "notes": "Likely a targeted spearphishing campaign. The IT support lure is consistent with business email compromise patterns.",
        "iocs": ["login-portal-verify[.]com", "195.22.127.14", "it-support-helpdesk[.]net"],
        "days_ago": 0,
    },
    {
        "subject": "Invoice #INV-2026-0341 Attached",
        "score": 74, "level": "High",
        "summary": "A malicious invoice email with an executable attachment was detected. The attachment extension is disguised using a double extension and the sender domain was registered 3 days ago.",
        "findings": [
            "Attachment: Invoice_March2026.pdf.exe (double extension disguise)",
            "Sender domain 'billingdept-invoices.com' registered 3 days ago",
            "MalwareBazaar match: SHA256 of attachment flagged as AgentTesla dropper",
            "Reply-To differs from From address",
            "No SPF record for sending domain",
        ],
        "techniques": [
            ("T1566.001", "Phishing: Spearphishing Attachment", "Email carries a malicious file disguised as a legitimate invoice document."),
            ("T1204.002", "User Execution: Malicious File", "Attachment requires user to open or execute it to trigger the payload."),
            ("T1027", "Obfuscated Files or Information", "Double extension (.pdf.exe) is used to disguise the true file type from the recipient."),
        ],
        "actions": [
            "Quarantine attachment across all mailboxes",
            "Block sender domain at the email gateway",
            "Run EDR scan on any host where attachment was opened",
        ],
        "notes": "AgentTesla is a commodity infostealer. Investigate whether other users in the organization received the same lure.",
        "iocs": ["billingdept-invoices[.]com", "a3f4c12...sha256", "Invoice_March2026.pdf.exe"],
        "days_ago": 1,
    },
    {
        "subject": "FW: Shared Document - Q1 Budget Review",
        "score": 61, "level": "High",
        "summary": "A forwarded document lure containing a credential harvesting link was identified. The link resolves to a fake OneDrive login page hosted on a recently registered domain.",
        "findings": [
            "URL 'onedrive-shared-docs.net' mimics Microsoft OneDrive",
            "Domain registered 11 days ago via Namecheap",
            "AbuseIPDB confidence score: 67 for hosting IP",
            "SPF passed but DKIM and DMARC absent",
            "No attachment — link-only vector",
        ],
        "techniques": [
            ("T1566.002", "Phishing: Spearphishing Link", "Email contains a link to an external page designed to steal credentials."),
            ("T1583.001", "Acquire Infrastructure: Domains", "Attacker registered a lookalike domain to impersonate a trusted cloud service."),
            ("T1056", "Input Capture", "Fake OneDrive login page captures entered credentials and exfiltrates them."),
        ],
        "actions": [
            "Block 'onedrive-shared-docs.net' at DNS and proxy layer",
            "Notify users who received the email to not click the link",
            "Check proxy logs for outbound connections to the identified IP",
        ],
        "notes": "The use of a OneDrive lure is common in business email compromise campaigns targeting Office 365 credentials.",
        "iocs": ["onedrive-shared-docs[.]net", "91.108.56.22"],
        "days_ago": 2,
    },
    {
        "subject": "Zoom Meeting Invitation - Tomorrow 9AM",
        "score": 45, "level": "Medium",
        "summary": "A suspicious Zoom meeting invitation was detected. The sender domain differs from a legitimate Zoom address and the meeting link resolves to a third-party host rather than zoom.us.",
        "findings": [
            "Link host is 'zoom-meetings-join.info' rather than zoom.us",
            "Sender domain 'zoom-notifications.com' is not affiliated with Zoom Video Communications",
            "Domain age: 22 days",
            "VT detections: 2/74 for link domain (low confidence)",
            "SPF passed for sending domain",
        ],
        "techniques": [
            ("T1566.002", "Phishing: Spearphishing Link", "Meeting invitation link redirects to a non-Zoom host which may harvest credentials or deliver malware."),
            ("T1036", "Masquerading", "Sender and link domain mimic Zoom branding to appear legitimate."),
        ],
        "actions": [
            "Do not join the meeting via the provided link",
            "Verify the meeting invitation directly with the purported sender",
            "Block 'zoom-meetings-join.info' as a precaution",
        ],
        "notes": "Risk level is medium — could be a credential harvest or malware delivery. Awaiting VT community votes on the domain.",
        "iocs": ["zoom-meetings-join[.]info", "zoom-notifications[.]com"],
        "days_ago": 3,
    },
    {
        "subject": "Your AWS bill is ready",
        "score": 38, "level": "Medium",
        "summary": "A billing notification impersonating Amazon Web Services was detected. The sender domain does not match AWS infrastructure but threat intel shows no confirmed malicious indicators at this time.",
        "findings": [
            "Sender: 'billing@aws-billing-alerts.com' (not an official AWS domain)",
            "Domain registered 45 days ago",
            "No malicious indicators found in VT or AbuseIPDB",
            "DMARC not configured for sending domain",
            "Link resolves to a redirect chain — final destination could not be confirmed",
        ],
        "techniques": [
            ("T1566", "Phishing", "Email impersonates a cloud billing notification to prompt user action on a suspicious link."),
        ],
        "actions": [
            "Confirm billing status directly at console.aws.amazon.com",
            "Do not click the link in the email",
            "Flag sender domain for monitoring",
        ],
        "notes": "Low threat intel hits but suspicious domain pattern warrants medium classification. Monitor for escalation.",
        "iocs": ["aws-billing-alerts[.]com"],
        "days_ago": 4,
    },
    {
        "subject": "Security Alert: New Login from Unknown Device",
        "score": 29, "level": "Medium",
        "summary": "A security alert notification was analyzed. The email is consistent with a legitimate login alert format but contains minor anomalies in the sender domain.",
        "findings": [
            "Sender domain 'account-security-alerts.net' is not an official vendor domain",
            "No malicious URL or attachment detected",
            "VT: 0/74 detections for all extracted IOCs",
            "AbuseIPDB: sending IP has no abuse reports",
            "DKIM passed — domain is authenticated",
        ],
        "techniques": [],
        "actions": [
            "Verify whether a legitimate login alert was expected",
            "Check account activity directly in the affected service",
        ],
        "notes": "Low risk. No confirmed malicious indicators. Possibly a third-party notification service. Monitor sender domain.",
        "iocs": ["account-security-alerts[.]net"],
        "days_ago": 5,
    },
    {
        "subject": "HR: Open Enrollment Closes Friday",
        "score": 15, "level": "Low",
        "summary": "A routine HR open enrollment reminder was analyzed. No malicious indicators were detected. Sender domain matches the known HR vendor.",
        "findings": [
            "Sender domain matches known HR platform vendor",
            "No malicious URLs or attachments",
            "SPF, DKIM, and DMARC all passed",
            "VT: 0/74 for all extracted IOCs",
            "No urgency language or spoofing signals",
        ],
        "techniques": [],
        "actions": ["No action required. Email appears legitimate."],
        "notes": "Benign. Submitted for baseline analysis.",
        "iocs": [],
        "days_ago": 6,
    },
    {
        "subject": "CRITICAL: CVE-2026-1234 Exploitation Detected in Logs",
        "score": 91, "level": "Critical",
        "summary": "A SIEM alert indicating active exploitation of CVE-2026-1234 was triaged. The source IP has a high AbuseIPDB confidence score and matches a known threat actor infrastructure cluster.",
        "findings": [
            "CVE-2026-1234: CVSS 9.8 — Remote Code Execution in Apache HTTP Server",
            "Source IP 185.220.101.45: AbuseIPDB confidence 94%, 1,847 reports",
            "Log pattern matches known exploit payload for this CVE",
            "Destination is a public-facing web server",
            "Alert fired on 3 separate log entries within 60 seconds",
        ],
        "techniques": [
            ("T1190", "Exploit Public-Facing Application", "Attacker is actively exploiting a known CVE in the public-facing web server."),
            ("T1110", "Brute Force", "Multiple sequential requests suggest automated exploitation tooling."),
            ("T1133", "External Remote Services", "Exploit targets an externally accessible service endpoint."),
        ],
        "actions": [
            "Block source IP 185.220.101.45 at the perimeter firewall immediately",
            "Apply Apache patch for CVE-2026-1234 or take service offline",
            "Preserve web server logs for forensic review",
            "Check for successful exploitation indicators (new processes, outbound connections)",
        ],
        "notes": "High confidence exploitation attempt. IP is part of a Tor exit node cluster commonly used by automated scanners and threat actors. Treat as active incident.",
        "iocs": ["185.220.101.45", "CVE-2026-1234"],
        "days_ago": 1,
    },
    {
        "subject": "RE: Contract Review - Please Sign",
        "score": 68, "level": "High",
        "summary": "A reply-chain hijacking phishing email was detected. The message appears to be inserted into an existing email thread but the sender address and link destination are external and suspicious.",
        "findings": [
            "Subject prefix 'RE:' suggests thread hijack but no prior thread found in mailbox",
            "DocuSign-lookalike domain 'docusign-contract-sign.com' in embedded link",
            "Sender domain 'legal-review-portal.net' registered 8 days ago",
            "VT: 5/74 for embedded link domain",
            "SPF failed for sender domain",
        ],
        "techniques": [
            ("T1566.002", "Phishing: Spearphishing Link", "Embedded link leads to a fake DocuSign page to harvest credentials."),
            ("T1534", "Internal Spearphishing", "Reply-chain format is used to create a false sense of legitimacy and trust."),
            ("T1583.001", "Acquire Infrastructure: Domains", "Attacker registered a lookalike domain to impersonate DocuSign."),
        ],
        "actions": [
            "Block 'docusign-contract-sign.com' at proxy and email gateway",
            "Notify recipient not to sign or click",
            "Investigate whether the original thread was compromised",
        ],
        "notes": "Reply-chain hijacking (thread hijack phishing) is a sophisticated technique used in targeted BEC campaigns. Escalate to tier 2 if recipient has finance or executive role.",
        "iocs": ["docusign-contract-sign[.]com", "legal-review-portal[.]net", "104.21.88.31"],
        "days_ago": 7,
    },
    {
        "subject": "Package Delivery Notification - Action Required",
        "score": 33, "level": "Medium",
        "summary": "A parcel delivery phishing lure was detected. The sender impersonates a shipping carrier with a link to a fake tracking page. Threat intel confidence is low.",
        "findings": [
            "Sender: 'noreply@fedex-delivery-alerts.info' — not an official FedEx domain",
            "Link: 'track-your-parcel.info/pkg?id=...'",
            "Domain age: 31 days — recently registered",
            "VT: 1/74 detection — low confidence",
            "AbuseIPDB: 0 reports for hosting IP",
        ],
        "techniques": [
            ("T1566.002", "Phishing: Spearphishing Link", "Parcel tracking link may lead to credential harvest or malware download."),
            ("T1036", "Masquerading", "Sender mimics FedEx branding in display name and domain."),
        ],
        "actions": [
            "Do not click the tracking link",
            "Verify delivery status directly at fedex.com using a known tracking number",
        ],
        "notes": "Common smishing/phishing lure. Low threat intel but suspicious domain pattern. Medium risk pending further intelligence.",
        "iocs": ["fedex-delivery-alerts[.]info", "track-your-parcel[.]info"],
        "days_ago": 8,
    },
    {
        "subject": "Suspicious Outbound Traffic - 10.0.1.45 to 185.130.5.12",
        "score": 78, "level": "Critical",
        "summary": "A SIEM alert for unusual outbound data transfer was triaged. The destination IP is associated with known C2 infrastructure and the volume of traffic is anomalous for the source host.",
        "findings": [
            "Source host 10.0.1.45 (Finance workstation) transferred 2.1 GB in 4 hours",
            "Destination 185.130.5.12: AbuseIPDB confidence 88%, associated with Cobalt Strike C2",
            "Traffic on port 443 with unusual SNI values",
            "No corresponding business process justifies this transfer volume",
            "First time this host has communicated with this destination",
        ],
        "techniques": [
            ("T1041", "Exfiltration Over C2 Channel", "Large data transfer over an encrypted channel to a known C2 IP suggests active exfiltration."),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "Traffic uses HTTPS to blend in with legitimate web traffic."),
            ("T1486", "Data Encrypted for Impact", "Encrypted channel makes content inspection difficult without SSL inspection."),
        ],
        "actions": [
            "Isolate host 10.0.1.45 from the network immediately",
            "Block 185.130.5.12 at the perimeter firewall",
            "Preserve forensic image of the host before remediation",
            "Initiate incident response — potential data breach",
        ],
        "notes": "High severity. Finance workstation exfiltrating 2.1GB to confirmed C2 infrastructure is a critical incident. Escalate immediately.",
        "iocs": ["185.130.5.12", "10.0.1.45"],
        "days_ago": 2,
    },
    {
        "subject": "Your Microsoft 365 subscription is expiring",
        "score": 21, "level": "Low",
        "summary": "A Microsoft 365 subscription renewal notification was analyzed. Sender domain matches a known Microsoft notification service. No malicious indicators detected.",
        "findings": [
            "Sender domain validated against known Microsoft notification domains",
            "SPF, DKIM, and DMARC all passed",
            "Link resolves to microsoft.com — no redirect chain",
            "VT: 0/74 for all IOCs",
            "No suspicious language or urgency manipulation",
        ],
        "techniques": [],
        "actions": ["No action required. Email appears to be a legitimate Microsoft notification."],
        "notes": "Benign. Submitted by user who was uncertain about the legitimacy of the email.",
        "iocs": [],
        "days_ago": 9,
    },
    {
        "subject": "Payroll Update: Direct Deposit Change Confirmation",
        "score": 87, "level": "Critical",
        "summary": "A business email compromise (BEC) payroll diversion attempt was detected. The email impersonates HR and requests direct deposit account changes, a classic financial fraud pattern.",
        "findings": [
            "Sender: display name matches HR director but domain is 'hr-payroll-update.com'",
            "Email requests employee banking information via reply",
            "No URL or attachment — pure social engineering",
            "Domain registered 2 days ago",
            "DMARC failed — domain has no alignment with corporate domain",
            "Urgency language: 'Please confirm before end of business today'",
        ],
        "techniques": [
            ("T1566.003", "Phishing: Spearphishing via Service", "BEC attempt uses impersonation of a trusted internal role to manipulate a financial process."),
            ("T1598", "Phishing for Information", "Email is designed to elicit sensitive banking information via reply rather than a link."),
            ("T1036", "Masquerading", "Display name matches a real employee while the sending domain is attacker-controlled."),
        ],
        "actions": [
            "Do not reply with any banking or payroll information",
            "Alert HR department immediately — verify with HR director via phone",
            "Block 'hr-payroll-update.com' at the email gateway",
            "Report to finance team to flag any pending payroll changes",
        ],
        "notes": "Classic BEC payroll diversion. No technical IOCs to block but organizational impact is high. Treat as priority incident.",
        "iocs": ["hr-payroll-update[.]com"],
        "days_ago": 3,
    },
    {
        "subject": "Newsletter: Security Weekly Digest",
        "score": 8, "level": "Low",
        "summary": "A routine security newsletter was analyzed at user request. No malicious indicators detected. Sender is a known security publication.",
        "findings": [
            "Sender domain matches known security publication",
            "All links resolve to the publication's official domain",
            "SPF and DKIM passed",
            "No suspicious content or urgency language",
        ],
        "techniques": [],
        "actions": ["No action required."],
        "notes": "Benign newsletter. Submitted for completeness.",
        "iocs": [],
        "days_ago": 10,
    },
    {
        "subject": "Failed Login Attempts - Admin Account",
        "score": 55, "level": "High",
        "summary": "A SIEM alert for repeated failed authentication attempts against an administrative account was triaged. The source IP has moderate abuse history and the pattern matches a credential stuffing attack.",
        "findings": [
            "47 failed login attempts against admin@company.com in 8 minutes",
            "Source IP 91.92.128.44: AbuseIPDB confidence 71%, 312 reports",
            "Attempts distributed across multiple user agents — automation detected",
            "No successful login observed yet",
            "MFA is enabled on target account",
        ],
        "techniques": [
            ("T1110.004", "Brute Force: Credential Stuffing", "Automated tool is testing credentials at scale against the admin account."),
            ("T1078", "Valid Accounts", "Attacker is attempting to gain access using potentially leaked credentials."),
        ],
        "actions": [
            "Block source IP 91.92.128.44 at the perimeter",
            "Temporarily lock the targeted admin account and notify the account owner",
            "Review authentication logs for any successful logins from this IP",
            "Consider geo-blocking or rate limiting login endpoints",
        ],
        "notes": "MFA provides significant protection here. Monitor for successful authentication. If account has no MFA, treat as critical.",
        "iocs": ["91.92.128.44"],
        "days_ago": 5,
    },
]

def level_to_score_check(score):
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    else:
        return "Low"

base_date = datetime(2026, 4, 22, 9, 0, 0)

for i, sample in enumerate(SAMPLES):
    days_ago = sample["days_ago"]
    hour_offset = random.randint(0, 8)
    minute_offset = random.randint(0, 59)
    dt = datetime(2026, 5, 1, 10, 0, 0) - timedelta(days=days_ago, hours=hour_offset, minutes=minute_offset)

    subject = sample["subject"]
    score = sample["score"]
    level = sample["level"]
    stem = dt.strftime("%Y%m%d_%H%M%S") + f"_{subject[:40].replace('/', '-')}"

    ioc_lines = "\n".join(f"- `{ioc}`" for ioc in sample["iocs"]) if sample["iocs"] else "- None identified"
    finding_lines = "\n".join(f"- {f}" for f in sample["findings"])
    mitre_lines = "\n".join(
        f"- [{tid}] {name}: {desc}" for tid, name, desc in sample["techniques"]
    ) if sample["techniques"] else "- No techniques mapped at this confidence threshold"
    action_lines = "\n".join(f"- {a}" for a in sample["actions"])

    md = f"""# SOC Report — {subject}
**Date:** {dt.isoformat()}
**Risk Score:** {score}/100 ({level})

## Executive Summary
{sample["summary"]}

## Technical Findings
{finding_lines}

## Indicators of Compromise
{ioc_lines}

## MITRE ATT&CK
{mitre_lines}

## Recommended Actions
{action_lines}

## Analyst Notes
{sample["notes"]}

---
_Defensive security education only. Validate all findings manually._"""

    path = REPORTS_DIR / f"{stem}.md"
    path.write_text(md)
    print(f"[+] {level:8s} {score:3d}/100  {subject[:50]}")

print(f"\nDone — {len(SAMPLES)} demo reports written to {REPORTS_DIR}")
