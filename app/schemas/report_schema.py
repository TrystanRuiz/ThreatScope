from pydantic import BaseModel
from typing import Optional

class MitreTechnique(BaseModel):
    id: str
    name: str
    confidence: str
    url: str

class ScoreBreakdown(BaseModel):
    score: int
    level: str
    breakdown: dict[str, int]

class SOCReport(BaseModel):
    executive_summary: str
    technical_findings: list[str]
    ioc_summary: str
    mitre_summary: str
    risk_assessment: str
    recommended_actions: list[str]
    analyst_notes: str
    score: Optional[ScoreBreakdown] = None
    mitre_techniques: Optional[list[MitreTechnique]] = None
