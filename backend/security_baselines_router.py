import json
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import SecurityBaseline, AuditLog, User
from rbac import require_role

router = APIRouter(
    prefix="/admin/security-baselines",
    tags=["Security Baselines"]
)


class BaselineCreate(BaseModel):
    name: str
    framework: str
    category: str
    description: str
    severity: str = "MEDIUM"
    enabled: bool = True
    baseline_content: Optional[str] = None


class BaselineUpdate(BaseModel):
    name: Optional[str] = None
    framework: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    baseline_content: Optional[str] = None


def record_audit(db, request, current_user, action, details):
    db.add(
        AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action=action,
            module="Security Baselines",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=details,
        )
    )


@router.get("")
def list_baselines(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    return db.query(SecurityBaseline).order_by(
        SecurityBaseline.created_at.desc()
    ).all()


@router.post("")
def create_baseline(
    payload: BaselineCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    if db.query(SecurityBaseline).filter(
        SecurityBaseline.name == payload.name
    ).first():
        raise HTTPException(status_code=409, detail="Baseline name already exists")

    baseline = SecurityBaseline(**payload.model_dump())
    db.add(baseline)
    db.flush()

    record_audit(
        db, request, current_user,
        "Security baseline created",
        f"Created baseline id={baseline.id}; name={baseline.name}; framework={baseline.framework}"
    )

    db.commit()
    db.refresh(baseline)
    return baseline


@router.put("/{baseline_id}")
def update_baseline(
    baseline_id: int,
    payload: BaselineUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    baseline = db.query(SecurityBaseline).filter(
        SecurityBaseline.id == baseline_id
    ).first()

    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")

    changes = payload.model_dump(exclude_unset=True)

    if "name" in changes:
        duplicate = db.query(SecurityBaseline).filter(
            SecurityBaseline.name == changes["name"],
            SecurityBaseline.id != baseline_id
        ).first()
        if duplicate:
            raise HTTPException(status_code=409, detail="Baseline name already exists")

    before = {
        key: getattr(baseline, key)
        for key in changes
    }

    for key, value in changes.items():
        setattr(baseline, key, value)

    record_audit(
        db, request, current_user,
        "Security baseline updated",
        f"Baseline id={baseline.id}; before={json.dumps(before, default=str)}; after={json.dumps(changes, default=str)}"
    )

    db.commit()
    db.refresh(baseline)
    return baseline


@router.patch("/{baseline_id}/status")
def update_baseline_status(
    baseline_id: int,
    enabled: bool,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    baseline = db.query(SecurityBaseline).filter(
        SecurityBaseline.id == baseline_id
    ).first()

    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")

    old_status = baseline.enabled
    baseline.enabled = enabled

    record_audit(
        db, request, current_user,
        "Security baseline status changed",
        f"Baseline id={baseline.id}; enabled changed from {old_status} to {enabled}"
    )

    db.commit()
    db.refresh(baseline)
    return baseline


@router.delete("/{baseline_id}")
def delete_baseline(
    baseline_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    baseline = db.query(SecurityBaseline).filter(
        SecurityBaseline.id == baseline_id
    ).first()

    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found")

    details = (
        f"Deleted baseline id={baseline.id}; name={baseline.name}; "
        f"framework={baseline.framework}"
    )

    record_audit(
        db, request, current_user,
        "Security baseline deleted",
        details
    )

    db.delete(baseline)
    db.commit()
    return {"message": "Security baseline deleted successfully"}
