from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class ComplianceControlBase(BaseModel):
    standard: str
    control_id: str
    control_name: str
    description: Optional[str] = None


class ComplianceControlCreate(ComplianceControlBase):
    pass


class ComplianceControlUpdate(BaseModel):
    status: Optional[str] = None
    score: Optional[float] = None
    findings: Optional[str] = None


class ComplianceControlResponse(ComplianceControlBase):
    id: int
    status: str
    score: float
    findings: Optional[str]
    last_assessed: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class ComplianceStandardStats(BaseModel):
    standard: str
    total_controls: int
    compliant: int
    partial: int
    non_compliant: int
    score: float


class ComplianceDashboard(BaseModel):
    overall_score: float
    standards: List[ComplianceStandardStats]
    critical_findings: int
