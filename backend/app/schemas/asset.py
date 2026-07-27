from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AssetBase(BaseModel):
    name: str
    asset_type: str
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    description: Optional[str] = None
    criticality: Optional[str] = "medium"


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    criticality: Optional[str] = None
    cpu_usage: Optional[float] = None
    ram_usage: Optional[float] = None


class AssetResponse(AssetBase):
    id: int
    status: str
    cpu_usage: float
    ram_usage: float
    last_scan: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class AssetStats(BaseModel):
    total: int
    online: int
    offline: int
    servers: int
    endpoints: int
    web_apps: int
