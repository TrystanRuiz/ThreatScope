import whois
from datetime import datetime, timezone
from app.utils.logger import get_logger

log = get_logger(__name__)

def lookup_domain(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age_days = None
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation_date).days

        return {
            "domain": domain,
            "registrar": w.registrar or "unknown",
            "creation_date": str(creation_date) if creation_date else "unknown",
            "age_days": age_days,
            "newly_registered": age_days is not None and age_days < 30,
            "country": w.country or "unknown",
        }
    except Exception as e:
        log.warning(f"WHOIS lookup failed for {domain}: {e}")
        return {
            "domain": domain,
            "registrar": "unknown",
            "creation_date": "unknown",
            "age_days": None,
            "newly_registered": False,
            "country": "unknown",
            "error": str(e),
        }
