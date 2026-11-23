from datetime import datetime
import socket
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.orm import Session

from database import Base, get_db
from models import User
from rbac import require_role

router = APIRouter(prefix="/assets", tags=["Asset Inventory"])


class Asset(Base):
    __tablename__ = "soc_assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    asset_type = Column(String(60), nullable=False, default="Server")
    ip_address = Column(String(100), nullable=True, index=True)
    url = Column(String(2048), nullable=True)
    hostname = Column(String(255), nullable=True)
    environment = Column(String(60), nullable=False, default="Production")
    status = Column(String(40), nullable=False, default="Active")
    criticality = Column(String(30), nullable=False, default="Medium")
    owner = Column(String(200), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow,
        onupdate=datetime.utcnow, nullable=False
    )


class AssetReachability(Base):
    __tablename__ = "soc_asset_reachability"

    asset_id = Column(Integer, primary_key=True)
    port = Column(Integer, nullable=True)
    status = Column(String(30), nullable=False, default="unknown")
    reason = Column(Text, nullable=True)
    checked_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    duration_ms = Column(Integer, nullable=False, default=0)


class AssetInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    asset_type: str = Field(default="Server", max_length=60)
    ip_address: str | None = Field(default=None, max_length=100)
    url: str | None = Field(default=None, max_length=2048)
    hostname: str | None = Field(default=None, max_length=255)
    environment: str = Field(default="Production", max_length=60)
    status: str = Field(default="Active", max_length=40)
    criticality: str = Field(default="Medium", max_length=30)
    owner: str | None = Field(default=None, max_length=200)
    notes: str | None = None


def asset_dict(asset):
    return {
        "id": asset.id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "ip_address": asset.ip_address,
        "url": asset.url,
        "hostname": asset.hostname,
        "environment": asset.environment,
        "status": asset.status,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "notes": asset.notes,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "updated_at": asset.updated_at.isoformat() if asset.updated_at else None,
    }


@router.get("")
def list_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    assets = db.query(Asset).order_by(Asset.id.desc()).all()
    return {"total": len(assets), "assets": [asset_dict(a) for a in assets]}


@router.post("", status_code=201)
def create_asset(
    data: AssetInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    asset = Asset(**data.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset_dict(asset)


@router.put("/{asset_id}")
def update_asset(
    asset_id: int,
    data: AssetInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    for key, value in data.model_dump().items():
        setattr(asset, key, value)

    db.commit()
    db.refresh(asset)
    return asset_dict(asset)


@router.delete("/{asset_id}")
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    db.delete(asset)
    db.commit()
    return {"message": "Asset deleted", "id": asset_id}


@router.get("/reachability/latest")
def get_latest_reachability(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    """Return saved latest reachability results for registered assets."""
    rows = db.query(AssetReachability).all()
    return {
        "total": len(rows),
        "results": [
            {
                "asset_id": row.asset_id,
                "port": row.port,
                "status": row.status,
                "reason": row.reason,
                "checked_at": row.checked_at.isoformat() + "Z",
                "duration_ms": row.duration_ms,
            }
            for row in rows
        ],
    }


@router.get("/{asset_id}/reachability")
def check_asset_reachability(
    asset_id: int,
    port: int = 443,
    timeout: float = 2.0,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    """Check and persist TCP reachability for a registered asset."""
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=400, detail="Port must be between 1 and 65535")
    if not 0.2 <= timeout <= 5.0:
        raise HTTPException(status_code=400, detail="Timeout must be between 0.2 and 5 seconds")

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    target = (asset.ip_address or "").strip()
    status = "unknown"
    reason = None
    duration_ms = 0
    checked_at = datetime.utcnow()

    if not target:
        reason = "No IP address is registered for this asset"
    else:
        import ipaddress
        try:
            parsed_ip = ipaddress.ip_address(target)
        except ValueError:
            reason = "Registered target is not a valid IP address"
        else:
            started = time.monotonic()
            status = "unreachable"
            try:
                with socket.create_connection((str(parsed_ip), port), timeout=timeout):
                    status = "reachable"
            except (socket.timeout, TimeoutError):
                reason = "Connection timed out"
            except OSError as exc:
                reason = str(exc)[:200]
            finally:
                duration_ms = round((time.monotonic() - started) * 1000)

            target = str(parsed_ip)

    checked_at = datetime.utcnow()
    row = db.query(AssetReachability).filter(
        AssetReachability.asset_id == asset.id
    ).first()

    if row is None:
        row = AssetReachability(asset_id=asset.id)
        db.add(row)

    row.port = port
    row.status = status
    row.reason = reason
    row.checked_at = checked_at
    row.duration_ms = duration_ms
    db.commit()
    db.refresh(row)

    return {
        "asset_id": asset.id,
        "target": target or None,
        "port": row.port,
        "status": row.status,
        "reason": row.reason,
        "checked_at": row.checked_at.isoformat() + "Z",
        "duration_ms": row.duration_ms,
    }


# Owned discovery observations share the administrative asset authorization boundary.
from admin_discovered_servers import router as discovered_servers_router
router.include_router(discovered_servers_router)
