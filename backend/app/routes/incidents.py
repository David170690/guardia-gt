from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import require_operator
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.user import User
from app.schemas.incident import IncidentCreate, IncidentResponse, IncidentStats, IncidentUpdate

router = APIRouter()

ACTIVE_STATUSES = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)


@router.get("/", response_model=List[IncidentResponse])
def list_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    organization: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)
    if organization:
        query = query.filter(Incident.organization == organization)
    return query.order_by(Incident.detected_at.desc()).offset(skip).limit(min(limit, 500)).all()


@router.get("/stats", response_model=IncidentStats)
def get_incident_stats(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()
    active = [i for i in incidents if i.status in ACTIVE_STATUSES]

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)
    resolved_today = sum(
        1 for i in incidents
        if i.resolved_at and i.resolved_at >= since
    )

    # MTTR real: promedio de detección a resolución sobre los incidentes que tienen
    # ambas marcas de tiempo. Sin datos suficientes se devuelve `None`, no un número inventado.
    durations = [
        (i.resolved_at - i.detected_at).total_seconds() / 60
        for i in incidents
        if i.resolved_at and i.detected_at and i.resolved_at >= i.detected_at
    ]
    mttr = round(sum(durations) / len(durations)) if durations else None

    return IncidentStats(
        total=len(incidents),
        active=len(active),
        critical=sum(1 for i in active if i.severity == IncidentSeverity.CRITICAL),
        high=sum(1 for i in active if i.severity == IncidentSeverity.HIGH),
        resolved_today=resolved_today,
        mttr_minutes=mttr,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    return incident


@router.post("/", response_model=IncidentResponse, status_code=201)
def create_incident(
    incident: IncidentCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_operator),
):
    db_incident = Incident(**incident.model_dump())
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return db_incident


@router.put("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    incident: IncidentUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_operator),
):
    db_incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not db_incident:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")

    for key, value in incident.model_dump(exclude_unset=True).items():
        setattr(db_incident, key, value)

    # Sella las marcas de tiempo del ciclo de vida para que el MTTR sea calculable.
    now = datetime.now(timezone.utc)
    if db_incident.status == IncidentStatus.CONTAINED and not db_incident.contained_at:
        db_incident.contained_at = now
    if db_incident.status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED) and not db_incident.resolved_at:
        db_incident.resolved_at = now

    db.commit()
    db.refresh(db_incident)
    return db_incident
