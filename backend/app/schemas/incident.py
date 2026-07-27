from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class IncidentBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    source_ip: Optional[str] = None
    affected_asset: Optional[str] = None


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    response_action: Optional[str] = None
    assigned_to: Optional[int] = None


class IncidentResponse(IncidentBase):
    id: int
    status: str
    response_action: Optional[str]
    assigned_to: Optional[int]
    detected_at: datetime
    contained_at: Optional[datetime]
    resolved_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class IncidentStats(BaseModel):
    total: int
    active: int
    critical: int
    high: int
    resolved_today: int
    mttr_minutes: int
