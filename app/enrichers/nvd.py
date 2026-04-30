import httpx
from app.utils.config import config
from app.utils.logger import get_logger

log = get_logger(__name__)

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def lookup_cve(cve_id: str) -> dict:
    if config.OFFLINE_MODE:
        return {"ioc": cve_id, "source": "nvd", "skipped": True, "reason": "offline"}

    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(BASE_URL, headers=headers, params={"cveId": cve_id.upper()})
            if resp.status_code == 200:
                vulns = resp.json().get("vulnerabilities", [])
                if not vulns:
                    return {"ioc": cve_id, "source": "nvd", "skipped": True, "reason": "not found"}
                cve = vulns[0].get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_score, severity = _extract_cvss(metrics)
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description available",
                )
                return {
                    "ioc": cve_id,
                    "source": "nvd",
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": desc[:300],
                    "published": cve.get("published", "unknown"),
                }
            elif resp.status_code == 429:
                return {"ioc": cve_id, "source": "nvd", "skipped": True, "reason": "rate limited"}
            else:
                return {"ioc": cve_id, "source": "nvd", "skipped": True, "reason": f"http {resp.status_code}"}
    except Exception as e:
        log.error(f"NVD error for {cve_id}: {e}")
        return {"ioc": cve_id, "source": "nvd", "skipped": True, "reason": str(e)}

def _extract_cvss(metrics: dict) -> tuple[float, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore", 0.0), data.get("baseSeverity", "unknown")
    return 0.0, "unknown"
