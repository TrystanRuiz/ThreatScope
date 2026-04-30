import re

def parse_headers(raw_headers: str) -> dict:
    headers = {}
    current_key = None
    for line in raw_headers.splitlines():
        if line.startswith((" ", "\t")) and current_key:
            headers[current_key] += " " + line.strip()
        elif ":" in line:
            key, _, val = line.partition(":")
            current_key = key.strip().lower()
            headers[current_key] = val.strip()

    received = _parse_received(raw_headers)
    routing_anomaly = _detect_routing_anomaly(received)

    return {
        "from": headers.get("from", ""),
        "reply_to": headers.get("reply-to", ""),
        "return_path": headers.get("return-path", ""),
        "subject": headers.get("subject", ""),
        "message_id": headers.get("message-id", ""),
        "date": headers.get("date", ""),
        "x_mailer": headers.get("x-mailer", ""),
        "received_chain": received,
        "routing_anomaly": routing_anomaly,
        "authentication_results": headers.get("authentication-results", ""),
        "dkim_signature_present": "dkim-signature" in headers,
    }

def _parse_received(raw: str) -> list[str]:
    return re.findall(r"Received:.*?(?=Received:|$)", raw, re.DOTALL | re.IGNORECASE)

def _detect_routing_anomaly(received: list[str]) -> bool:
    seen_ips = []
    for hop in received:
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", hop)
        seen_ips.extend(ips)
    unique = set(seen_ips)
    return len(unique) != len(seen_ips)
