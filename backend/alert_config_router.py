from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import AlertConfiguration, AuditLog, User
from rbac import require_role

router = APIRouter(
    prefix="/admin/alert-config",
    tags=["Alert Configuration"]
)


class AlertCreate(BaseModel):
    name: str
    category: str
    description: str
    severity: str = "MEDIUM"
    priority: str = "MEDIUM"
    source: Optional[str] = None
    event_type: Optional[str] = None
    threshold: Optional[int] = None
    time_window_minutes: Optional[int] = None
    conditions: Optional[str] = None
    notification_policy_id: Optional[int] = None
    enabled: bool = True


class AlertUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    threshold: Optional[int] = None
    time_window_minutes: Optional[int] = None
    conditions: Optional[str] = None
    notification_policy_id: Optional[int] = None
    enabled: Optional[bool] = None


def record_audit(db, request, user, action, details):
    db.add(AuditLog(
        user_id=user.id,
        username=user.username,
        action=action,
        module="Alert Configuration",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=details
    ))


@router.get("")
def list_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    return db.query(AlertConfiguration).order_by(
        AlertConfiguration.created_at.desc()
    ).all()


@router.post("")
def create_alert(
    payload: AlertCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    if db.query(AlertConfiguration).filter(
        AlertConfiguration.name == payload.name
    ).first():
        raise HTTPException(409, "Alert configuration already exists")

    if payload.notification_policy_id is not None:
        from models import NotificationPolicy
        policy = db.query(NotificationPolicy).filter(
            NotificationPolicy.id == payload.notification_policy_id
        ).first()
        if not policy:
            raise HTTPException(404, "Notification policy not found")

    item = AlertConfiguration(**payload.model_dump())
    db.add(item)
    db.flush()

    record_audit(
        db, request, current_user,
        "Alert configuration created",
        f"Created alert id={item.id}; name={item.name}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.put("/{alert_id}")
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(AlertConfiguration).filter(
        AlertConfiguration.id == alert_id
    ).first()

    if not item:
        raise HTTPException(404, "Alert configuration not found")

    changes = payload.model_dump(exclude_unset=True)

    if "name" in changes:
        duplicate = db.query(AlertConfiguration).filter(
            AlertConfiguration.name == changes["name"],
            AlertConfiguration.id != alert_id
        ).first()
        if duplicate:
            raise HTTPException(409, "Alert configuration name already exists")

    if changes.get("notification_policy_id") is not None:
        from models import NotificationPolicy
        policy = db.query(NotificationPolicy).filter(
            NotificationPolicy.id == changes["notification_policy_id"]
        ).first()
        if not policy:
            raise HTTPException(404, "Notification policy not found")

    before = {key: getattr(item, key) for key in changes}

    for key, value in changes.items():
        setattr(item, key, value)

    record_audit(
        db, request, current_user,
        "Alert configuration updated",
        f"Alert id={item.id}; before={before}; after={changes}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    request: Request,
    enabled: bool,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(AlertConfiguration).filter(
        AlertConfiguration.id == alert_id
    ).first()

    if not item:
        raise HTTPException(404, "Alert configuration not found")

    old_status = item.enabled
    item.enabled = enabled

    record_audit(
        db, request, current_user,
        "Alert configuration status changed",
        f"Alert id={item.id}; enabled changed from {old_status} to {enabled}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{alert_id}")
def delete_alert(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(AlertConfiguration).filter(
        AlertConfiguration.id == alert_id
    ).first()

    if not item:
        raise HTTPException(404, "Alert configuration not found")

    record_audit(
        db, request, current_user,
        "Alert configuration deleted",
        f"Deleted alert id={item.id}; name={item.name}"
    )

    db.delete(item)
    db.commit()
    return {"message": "Alert configuration deleted successfully"}
