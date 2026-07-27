from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.schemas.incident import IncidentCreate, IncidentUpdate, IncidentResponse, IncidentStats

router = APIRouter()


@router.get("/", response_model=List[IncidentResponse])
def list_incidents(
    severity: str = None,
    status: str = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    return query.order_by(Incident.detected_at.desc()).offset(skip).limit(limit).all()


@router.get("/stats", response_model=IncidentStats)
def get_incident_stats(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    active = [i for i in incidents if i.status in [IncidentStatus.OPEN, IncidentStatus.INVESTIGATING]]
    critical = sum(1 for i in active if i.severity == IncidentSeverity.CRITICAL)
    high = sum(1 for i in active if i.severity == IncidentSeverity.HIGH)
    resolved = [i for i in incidents if i.status == IncidentStatus.RESOLVED]
    mttr = 42
    return IncidentStats(
        total=len(incidents),
        active=len(active),
        critical=critical,
        high=high,
        resolved_today=len(resolved),
        mttr_minutes=mttr,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/", response_model=IncidentResponse)
def create_incident(incident: IncidentCreate, db: Session = Depends(get_db)):
    db_incident = Incident(**incident.model_dump())
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident


@router.put("/{incident_id}", response_model=IncidentResponse)
def update_incident(incident_id: int, incident: IncidentUpdate, db: Session = Depends(get_db)):
    db_incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not db_incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    update_data = incident.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_incident, key, value)
    db.commit()
    db.refresh(db_incident)
    return db_incident
