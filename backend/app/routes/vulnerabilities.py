from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import require_operator
from app.models.asset import Asset
from app.models.user import User
from app.models.vulnerability import Severity, Vulnerability, VulnStatus
from app.schemas.vulnerability import (
    VulnerabilityCreate,
    VulnerabilityResponse,
    VulnerabilityStats,
    VulnerabilityUpdate,
)

router = APIRouter()


@router.get("/", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    organization: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(Vulnerability)
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status:
        query = query.filter(Vulnerability.status == status)
    if organization:
        query = query.join(Asset, Vulnerability.asset_id == Asset.id).filter(
            Asset.organization == organization
        )
    return (
        query.order_by(Vulnerability.cvss_score.desc())
        .offset(skip)
        .limit(min(limit, 500))
        .all()
    )


@router.get("/stats", response_model=VulnerabilityStats)
def get_vulnerability_stats(db: Session = Depends(get_db)):
    vulns = db.query(Vulnerability).all()
    return VulnerabilityStats(
        total=len(vulns),
        critical=sum(1 for v in vulns if v.severity == Severity.CRITICAL),
        high=sum(1 for v in vulns if v.severity == Severity.HIGH),
        medium=sum(1 for v in vulns if v.severity == Severity.MEDIUM),
        low=sum(1 for v in vulns if v.severity == Severity.LOW),
        remediated=sum(1 for v in vulns if v.status == VulnStatus.REMEDIATED),
    )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidad no encontrada")
    return vuln


@router.post("/", response_model=VulnerabilityResponse, status_code=201)
def create_vulnerability(
    vuln: VulnerabilityCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_operator),
):
    db_vuln = Vulnerability(**vuln.model_dump())
    db.add(db_vuln)
    db.commit()
    db.refresh(db_vuln)
    return db_vuln


@router.put("/{vuln_id}", response_model=VulnerabilityResponse)
def update_vulnerability(
    vuln_id: int,
    vuln: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_operator),
):
    db_vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not db_vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidad no encontrada")

    for key, value in vuln.model_dump(exclude_unset=True).items():
        setattr(db_vuln, key, value)

    if db_vuln.status == VulnStatus.REMEDIATED and not db_vuln.remediated_at:
        db_vuln.remediated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(db_vuln)
    return db_vuln


@router.delete("/{vuln_id}")
def delete_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_operator),
):
    db_vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not db_vuln:
        raise HTTPException(status_code=404, detail="Vulnerabilidad no encontrada")
    db.delete(db_vuln)
    db.commit()
    return {"detail": "Vulnerabilidad eliminada"}
