import httpx
from app.utils.rate_limiter import RateLimiter
from app.utils.config import config
from app.utils.logger import get_logger

log = get_logger(__name__)
vt_limiter = RateLimiter(calls_per_minute=config.VT_CALLS_PER_MINUTE)

BASE_URL = "https://www.virustotal.com/api/v3"

async def lookup_domain(domain: str) -> dict:
    return await _get(f"{BASE_URL}/domains/{domain}", domain)

async def lookup_ip(ip: str) -> dict:
    return await _get(f"{BASE_URL}/ip_addresses/{ip}", ip)

async def lookup_url(url: str) -> dict:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return await _get(f"{BASE_URL}/urls/{url_id}", url)

async def lookup_hash(hash_val: str) -> dict:
    return await _get(f"{BASE_URL}/files/{hash_val}", hash_val)

async def _get(endpoint: str, label: str) -> dict:
    if config.OFFLINE_MODE or not config.VT_API_KEY:
        return {"ioc": label, "source": "virustotal", "skipped": True, "reason": "offline or no key"}

    await vt_limiter.acquire()
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(endpoint, headers={"x-apikey": config.VT_API_KEY})
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "ioc": label,
                    "source": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": data.get("reputation", None),
                    "community_score": data.get("total_votes", {}).get("malicious", 0),
                }
            elif resp.status_code == 404:
                return {"ioc": label, "source": "virustotal", "skipped": True, "reason": "not found"}
            elif resp.status_code == 429:
                log.warning(f"VirusTotal rate limit hit for {label}")
                return {"ioc": label, "source": "virustotal", "skipped": True, "reason": "rate limited"}
            else:
                return {"ioc": label, "source": "virustotal", "skipped": True, "reason": f"http {resp.status_code}"}
    except Exception as e:
        log.error(f"VirusTotal error for {label}: {e}")
        return {"ioc": label, "source": "virustotal", "skipped": True, "reason": str(e)}
