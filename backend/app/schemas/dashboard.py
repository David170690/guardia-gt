from pydantic import BaseModel
from typing import List, Optional


class KPICard(BaseModel):
    label: str
    value: str
    change: Optional[str] = None
    trend: Optional[str] = None


class ThreatItem(BaseModel):
    name: str
    severity: str
    count: int
    description: str


class RiskCategory(BaseModel):
    category: str
    score: int
    color: str


class DashboardResponse(BaseModel):
    risk_level: str
    risk_score: int
    vulnerabilities: KPICard
    compliance: KPICard
    assets: KPICard
    incidents: KPICard
    risk_categories: List[RiskCategory]
    active_threats: List[ThreatItem]
    recent_incidents: List[dict]
