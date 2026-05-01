import httpx
from app.utils.rate_limiter import RateLimiter
from app.utils.config import config
from app.utils.logger import get_logger

log = get_logger(__name__)

BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_limiter = RateLimiter(calls_per_minute=30)  # well within 1,000/day free tier

async def lookup_ip(ip: str) -> dict:
    if config.OFFLINE_MODE or not config.ABUSEIPDB_API_KEY:
        return {"ioc": ip, "source": "abuseipdb", "skipped": True, "reason": "offline or no key"}

    await _limiter.acquire()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                BASE_URL,
                headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "ioc": ip,
                    "source": "abuseipdb",
                    "abuse_confidence": d.get("abuseConfidenceScore", 0),
                    "country": d.get("countryCode", "unknown"),
                    "isp": d.get("isp", "unknown"),
                    "domain": d.get("domain", "unknown"),
                    "total_reports": d.get("totalReports", 0),
                    "is_whitelisted": d.get("isWhitelisted", False),
                }
            elif resp.status_code == 429:
                log.warning(f"AbuseIPDB daily limit hit for {ip}")
                return {"ioc": ip, "source": "abuseipdb", "skipped": True, "reason": "daily limit reached"}
            else:
                return {"ioc": ip, "source": "abuseipdb", "skipped": True, "reason": f"http {resp.status_code}"}
    except Exception as e:
        log.error(f"AbuseIPDB error for {ip}: {e}")
        return {"ioc": ip, "source": "abuseipdb", "skipped": True, "reason": str(e)}
