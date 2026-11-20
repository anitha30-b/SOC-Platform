from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import Optional

from database import get_db
from models import DetectionConfiguration, User, AuditLog
from rbac import require_role

router = APIRouter(
    prefix="/admin/detection-config",
    tags=["Detection Configuration"]
)


class DetectionCreate(BaseModel):
    name: str
    category: str
    description: str
    detection_type: str = "Rule-Based"
    severity: str = "MEDIUM"
    conditions: Optional[str] = None
    enabled: bool = True
    threshold: Optional[int] = Field(default=None, ge=1, le=2147483647)
    time_window_minutes: Optional[int] = Field(default=None, ge=1, le=1440)
    source: Optional[str] = Field(default=None, max_length=100)
    event_type: Optional[str] = Field(default=None, max_length=100)


class DetectionUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    detection_type: Optional[str] = None
    severity: Optional[str] = None
    conditions: Optional[str] = None
    enabled: Optional[bool] = None
    threshold: Optional[int] = Field(default=None, ge=1, le=2147483647)
    time_window_minutes: Optional[int] = Field(default=None, ge=1, le=1440)
    source: Optional[str] = Field(default=None, max_length=100)
    event_type: Optional[str] = Field(default=None, max_length=100)


def validate_threshold_fields(values):
    if str(values.get("detection_type") or "").strip().lower() == "threshold-based":
        if values.get("threshold") is None or values.get("time_window_minutes") is None:
            raise HTTPException(422, "Threshold-Based rules require events required and a time window.")


def record_audit(db, request, user, action, details):
    db.add(AuditLog(
        user_id=user.id,
        username=user.username,
        action=action,
        module="Detection Configuration",
        ip_address=request.client.host if request.client else None,
        status="SUCCESS",
        details=details
    ))


@router.get("")
def list_detections(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    return db.query(DetectionConfiguration).order_by(
        DetectionConfiguration.created_at.desc()
    ).all()


@router.post("")
def create_detection(
    payload: DetectionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    validate_threshold_fields(payload.model_dump())

    if db.query(DetectionConfiguration).filter(
        DetectionConfiguration.name == payload.name
    ).first():
        raise HTTPException(409, "Detection rule already exists")

    item = DetectionConfiguration(**payload.model_dump())
    db.add(item)
    db.flush()

    record_audit(
        db, request, current_user,
        "Detection configuration created",
        f"Created detection id={item.id}; name={item.name}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.put("/{detection_id}")
def update_detection(
    detection_id: int,
    payload: DetectionUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(DetectionConfiguration).filter(
        DetectionConfiguration.id == detection_id
    ).first()

    if not item:
        raise HTTPException(404, "Detection configuration not found")

    changes = payload.model_dump(exclude_unset=True)
    validate_threshold_fields({
        "detection_type": changes.get("detection_type", item.detection_type),
        "threshold": changes.get("threshold", item.threshold),
        "time_window_minutes": changes.get("time_window_minutes", item.time_window_minutes),
    })

    if "name" in changes:
        duplicate = db.query(DetectionConfiguration).filter(
            DetectionConfiguration.name == changes["name"],
            DetectionConfiguration.id != detection_id
        ).first()
        if duplicate:
            raise HTTPException(409, "Detection rule name already exists")

    before = {key: getattr(item, key) for key in changes}

    for key, value in changes.items():
        setattr(item, key, value)

    record_audit(
        db, request, current_user,
        "Detection configuration updated",
        f"Detection id={item.id}; before={before}; after={changes}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.patch("/{detection_id}/status")
def update_detection_status(
    detection_id: int,
    request: Request,
    enabled: bool,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(DetectionConfiguration).filter(
        DetectionConfiguration.id == detection_id
    ).first()

    if not item:
        raise HTTPException(404, "Detection configuration not found")

    if enabled:
        validate_threshold_fields({"detection_type": item.detection_type,
            "threshold": item.threshold, "time_window_minutes": item.time_window_minutes})

    old_status = item.enabled
    item.enabled = enabled

    record_audit(
        db, request, current_user,
        "Detection configuration status changed",
        f"Detection id={item.id}; enabled changed from {old_status} to {enabled}"
    )

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{detection_id}")
def delete_detection(
    detection_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3))
):
    item = db.query(DetectionConfiguration).filter(
        DetectionConfiguration.id == detection_id
    ).first()

    if not item:
        raise HTTPException(404, "Detection configuration not found")

    record_audit(
        db, request, current_user,
        "Detection configuration deleted",
        f"Deleted detection id={item.id}; name={item.name}"
    )

    db.delete(item)
    db.commit()
    return {"message": "Detection configuration deleted successfully"}
