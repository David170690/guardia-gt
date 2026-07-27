from sqlalchemy import Column, Integer, String, DateTime, Enum, Float, Text
from sqlalchemy.sql import func
from app.core.database import Base
import enum


class ComplianceStandard(str, enum.Enum):
    ISO_27001 = "iso_27001"
    NIST_CSF = "nist_csf"
    CIS_V8 = "cis_v8"
    OWASP_TOP10 = "owasp_top10"
    MITRE_ATTACK = "mitre_attack"


class ComplianceStatus(str, enum.Enum):
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id = Column(Integer, primary_key=True, index=True)
    standard = Column(Enum(ComplianceStandard), nullable=False)
    control_id = Column(String(50), nullable=False)
    control_name = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(ComplianceStatus), default=ComplianceStatus.NON_COMPLIANT)
    score = Column(Float, default=0.0)
    findings = Column(Text, nullable=True)
    last_assessed = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
