import json
import ollama
from app.utils.config import config
from app.utils.logger import get_logger

log = get_logger(__name__)

SYSTEM_PROMPT = """You are a SOC analyst assistant.
Use ONLY the evidence provided below.
Do not invent threat intelligence.
If evidence is missing, say "unknown" instead of guessing.
Be concise and professional. Respond ONLY in valid JSON."""

USER_TEMPLATE = """Analyze this security evidence and generate a SOC report.

Evidence:
{evidence}

Generate a JSON report with exactly these keys:
- executive_summary: string (2-3 sentences)
- technical_findings: list of strings
- ioc_summary: string
- mitre_summary: string
- risk_assessment: string
- recommended_actions: list of strings
- analyst_notes: string"""

def generate_report(evidence: dict) -> dict:
    prompt = USER_TEMPLATE.format(evidence=json.dumps(evidence, indent=2, default=str))
    try:
        response = ollama.chat(
            model=config.OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            format="json",
            options={"temperature": 0.1},
        )
        raw = response["message"]["content"]
        return json.loads(raw)
    except json.JSONDecodeError as e:
        log.error(f"LLM returned invalid JSON: {e}")
        return _fallback_report(evidence)
    except Exception as e:
        log.error(f"Ollama call failed: {e}")
        return _fallback_report(evidence)

def _fallback_report(evidence: dict) -> dict:
    return {
        "executive_summary": "LLM report generation failed. Review raw evidence manually.",
        "technical_findings": [],
        "ioc_summary": "See extracted IOCs above.",
        "mitre_summary": "See MITRE mapping above.",
        "risk_assessment": "Manual review required.",
        "recommended_actions": ["Review extracted IOCs manually", "Check enrichment results"],
        "analyst_notes": "Automated report unavailable. Evidence was parsed and scored successfully.",
    }
