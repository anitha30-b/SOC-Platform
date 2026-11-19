from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import RetentionPolicy, AuditLog, User
from rbac import require_role

router = APIRouter(
    prefix="/admin/retention",
    tags=["Retention Policies"]
)


class RetentionCreate(BaseModel):
    name: str
    data_type: str
    description: str
    retention_days: int = 90
    archive_enabled: bool = False
    archive_after_days: Optional[int] = None
    auto_delete: bool = False
    enabled: bool = True


class RetentionUpdate(BaseModel):
    name: Optional[str] = None
    data_type: Optional[str] = None
    description: Optional[str] = None
    retention_days: Optional[int] = None
    archive_enabled: Optional[bool] = None
    archive_after_days: Optional[int] = None
    auto_delete: Optional[bool] = None
    enabled: Optional[bool] = None


def record_audit(db, request, user, action, details):
    db.add(AuditLog(
        user_id=user.id,
        username=user.username,
        action=action,
        module="Retention Policies",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=details
    ))


@router.get("")
def list_retention_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    return db.query(RetentionPolicy).order_by(
        RetentionPolicy.created_at.desc()
    ).all()


@router.post("")
def create_retention_policy(
    payload: RetentionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    if db.query(RetentionPolicy).filter(
        RetentionPolicy.name == payload.name
    ).first():
        raise HTTPException(409, "Retention policy already exists")

    if payload.retention_days < 1:
        raise HTTPException(400, "Retention days must be at least 1")

    if payload.archive_enabled:
        if payload.archive_after_days is None or payload.archive_after_days < 1:
            raise HTTPException(400, "Enter valid archive days")
        if payload.archive_after_days > payload.retention_days:
            raise HTTPException(400, "Archive days cannot exceed retention days")

    item = RetentionPolicy(**payload.model_dump())
    db.add(item)
    db.flush()

    record_audit(
        db, request, current_user,
        "Retention policy created",
        f"Created retention id={item.id}; name={item.name}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.put("/{policy_id}")
def update_retention_policy(
    policy_id: int,
    payload: RetentionUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(RetentionPolicy).filter(
        RetentionPolicy.id == policy_id
    ).first()

    if not item:
        raise HTTPException(404, "Retention policy not found")

    changes = payload.model_dump(exclude_unset=True)

    if "name" in changes:
        duplicate = db.query(RetentionPolicy).filter(
            RetentionPolicy.name == changes["name"],
            RetentionPolicy.id != policy_id
        ).first()
        if duplicate:
            raise HTTPException(409, "Retention policy name already exists")

    new_days = changes.get("retention_days", item.retention_days)
    archive_enabled = changes.get("archive_enabled", item.archive_enabled)
    archive_days = changes.get("archive_after_days", item.archive_after_days)

    if new_days < 1:
        raise HTTPException(400, "Retention days must be at least 1")

    if archive_enabled:
        if archive_days is None or archive_days < 1:
            raise HTTPException(400, "Enter valid archive days")
        if archive_days > new_days:
            raise HTTPException(400, "Archive days cannot exceed retention days")

    before = {key: getattr(item, key) for key in changes}

    for key, value in changes.items():
        setattr(item, key, value)

    record_audit(
        db, request, current_user,
        "Retention policy updated",
        f"Retention id={item.id}; before={before}; after={changes}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.patch("/{policy_id}/status")
def update_retention_status(
    policy_id: int,
    request: Request,
    enabled: bool,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(RetentionPolicy).filter(
        RetentionPolicy.id == policy_id
    ).first()

    if not item:
        raise HTTPException(404, "Retention policy not found")

    old_status = item.enabled
    item.enabled = enabled

    record_audit(
        db, request, current_user,
        "Retention policy status changed",
        f"Retention id={item.id}; enabled changed from {old_status} to {enabled}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{policy_id}")
def delete_retention_policy(
    policy_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(RetentionPolicy).filter(
        RetentionPolicy.id == policy_id
    ).first()

    if not item:
        raise HTTPException(404, "Retention policy not found")

    record_audit(
        db, request, current_user,
        "Retention policy deleted",
        f"Deleted retention id={item.id}; name={item.name}"
    )

    db.delete(item)
    db.commit()
    return {"message": "Retention policy deleted successfully"}
