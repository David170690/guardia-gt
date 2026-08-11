from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import require_operator
from app.models.asset import Asset, AssetStatus, AssetType
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.asset import AssetCreate, AssetResponse, AssetStats, AssetUpdate

router = APIRouter()


@router.get("/", response_model=List[AssetResponse])
def list_assets(
    asset_type: Optional[str] = None,
    status: Optional[str] = None,
    organization: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    query = db.query(Asset)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if status:
        query = query.filter(Asset.status == status)
    if organization:
        query = query.filter(Asset.organization == organization)
    return query.order_by(Asset.id).offset(skip).limit(min(limit, 500)).all()


@router.get("/stats", response_model=AssetStats)
def get_asset_stats(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    return AssetStats(
        total=len(assets),
        online=sum(1 for a in assets if a.status == AssetStatus.ONLINE),
        offline=sum(1 for a in assets if a.status == AssetStatus.OFFLINE),
        servers=sum(1 for a in assets if a.asset_type == AssetType.SERVER),
        endpoints=sum(1 for a in assets if a.asset_type == AssetType.ENDPOINT),
        web_apps=sum(1 for a in assets if a.asset_type == AssetType.WEB_APP),
    )


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    return asset


@router.post("/", response_model=AssetResponse, status_code=201)
def create_asset(
    asset: AssetCreate,
    db: Session = Depends(get_db),
    _: User = Depends(require_operator),
):
    db_asset = Asset(**asset.model_dump())
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    asset: AssetUpdate,
    db: Session = Depends(get_db),
    _: User = Depends(require_operator),
):
    db_asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")
    for key, value in asset.model_dump(exclude_unset=True).items():
        setattr(db_asset, key, value)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.delete("/{asset_id}")
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_operator),
):
    db_asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Activo no encontrado")

    # Los hallazgos apuntan al activo por clave foránea: borrarlos primero evita
    # dejar filas huérfanas y el error de integridad al eliminar.
    db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id).delete(
        synchronize_session=False
    )
    db.delete(db_asset)
    db.commit()
    return {"detail": "Activo eliminado"}
