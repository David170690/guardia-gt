from sqlalchemy import Column, Integer, String, DateTime, Enum, Float
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class AssetType(str, enum.Enum):
    SERVER = "server"
    ENDPOINT = "endpoint"
    NETWORK = "network"
    WEB_APP = "web_app"
    DATABASE = "database"
    CLOUD = "cloud"
    OTHER = "other"


class AssetCriticality(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    asset_type = Column(Enum(AssetType), nullable=False)
    ip_address = Column(String(45), nullable=True)
    operating_system = Column(String(100), nullable=True)
    description = Column(String(500), nullable=True)
    criticality = Column(Enum(AssetCriticality), default=AssetCriticality.MEDIUM)
    status = Column(Enum(AssetStatus), default=AssetStatus.ONLINE)
    cpu_usage = Column(Float, default=0.0)
    ram_usage = Column(Float, default=0.0)
    last_scan = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
