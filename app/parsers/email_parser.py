import email
import re
from email import policy
from app.parsers.ioc_extractor import extract_all_iocs
from app.utils.logger import get_logger

log = get_logger(__name__)

URGENCY_PATTERNS = re.compile(
    r"\b(urgent|immediately|action required|verify now|suspended|limited time|click here|confirm your|unusual activity|security alert|your account)\b",
    re.IGNORECASE,
)

def parse_raw_email(raw: str) -> dict:
    try:
        msg = email.message_from_string(raw, policy=policy.default)
    except Exception as e:
        log.error(f"Failed to parse email: {e}")
        return {"error": str(e)}

    from_addr = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))
    subject = str(msg.get("Subject", ""))
    received = msg.get_all("Received", [])
    auth_results = str(msg.get("Authentication-Results", ""))

    body = _extract_body(msg)
    attachments = _extract_attachments(msg)

    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_to)
    return_domain = _extract_domain(return_path)

    sender_mismatch = bool(
        (reply_to and from_domain and reply_domain and from_domain != reply_domain)
        or (return_path and from_domain and return_domain and from_domain != return_domain)
    )

    spf = _check_auth(auth_results, "spf")
    dkim = _check_auth(auth_results, "dkim")
    dmarc = _check_auth(auth_results, "dmarc")

    urgency_hits = URGENCY_PATTERNS.findall(subject + " " + body)
    # Include headers in IOC extraction so IPs in Received: lines are found
    header_text = f"{from_addr} {reply_to} {return_path} {' '.join(str(r) for r in received)}"
    iocs = extract_all_iocs(body + " " + subject + " " + header_text)

    return {
        "from": from_addr,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "received_hops": len(received),
        "attachments": attachments,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "sender_mismatch": sender_mismatch,
        "urgency_phrases": list(set(urgency_hits)),
        "body_preview": body[:500],
        "iocs": iocs,
    }

def _extract_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = str(msg.get_payload(decode=True) or "")
    return body

def _extract_attachments(msg) -> list[str]:
    names = []
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            names.append(filename)
    return names

def _extract_domain(addr: str) -> str:
    match = re.search(r"@([\w.\-]+)", addr)
    return match.group(1).lower() if match else ""

def _check_auth(auth_results: str, protocol: str) -> str:
    pattern = re.compile(rf"{protocol}=(\w+)", re.IGNORECASE)
    match = pattern.search(auth_results)
    return match.group(1).lower() if match else "unknown"
