from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.models.compliance import ComplianceControl, ComplianceStandard, ComplianceStatus
from app.schemas.compliance import ComplianceControlCreate, ComplianceControlUpdate, ComplianceControlResponse, ComplianceDashboard

router = APIRouter()


@router.get("/", response_model=List[ComplianceControlResponse])
def list_controls(
    standard: str = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(ComplianceControl)
    if standard:
        query = query.filter(ComplianceControl.standard == standard)
    return query.offset(skip).limit(limit).all()


@router.get("/dashboard", response_model=ComplianceDashboard)
def get_compliance_dashboard(db: Session = Depends(get_db)):
    controls = db.query(ComplianceControl).all()
    standards = []
    for std in ComplianceStandard:
        std_controls = [c for c in controls if c.standard == std]
        total = len(std_controls) if std_controls else 1
        compliant = sum(1 for c in std_controls if c.status == ComplianceStatus.COMPLIANT)
        partial = sum(1 for c in std_controls if c.status == ComplianceStatus.PARTIAL)
        non_compliant = sum(1 for c in std_controls if c.status == ComplianceStatus.NON_COMPLIANT)
        score = (compliant / total * 100) if std_controls else 0
        standards.append({
            "standard": std.value,
            "total_controls": len(std_controls),
            "compliant": compliant,
            "partial": partial,
            "non_compliant": non_compliant,
            "score": round(score, 1),
        })
    total_all = len(controls) if controls else 1
    compliant_all = sum(1 for c in controls if c.status == ComplianceStatus.COMPLIANT)
    critical = sum(1 for c in controls if c.status == ComplianceStatus.NON_COMPLIANT and c.score < 50)
    return ComplianceDashboard(
        overall_score=round((compliant_all / total_all * 100), 1) if controls else 0,
        standards=standards,
        critical_findings=critical,
    )


@router.post("/", response_model=ComplianceControlResponse)
def create_control(control: ComplianceControlCreate, db: Session = Depends(get_db)):
    db_control = ComplianceControl(**control.model_dump())
    db.add(db_control)
    db.commit()
    db.refresh(db_control)
    return db_control


@router.put("/{control_id}", response_model=ComplianceControlResponse)
def update_control(control_id: int, control: ComplianceControlUpdate, db: Session = Depends(get_db)):
    db_control = db.query(ComplianceControl).filter(ComplianceControl.id == control_id).first()
    if not db_control:
        raise HTTPException(status_code=404, detail="Control not found")
    update_data = control.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_control, key, value)
    db.commit()
    db.refresh(db_control)
    return db_control
