from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import NotificationPolicy
from rbac import require_role


router = APIRouter(
    prefix="/admin/notification-policies",
    tags=["Admin Notification Policies"],
)


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class NotificationPolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    enabled: bool = True
    source: str | None = Field(default=None, max_length=100)
    event_type: str | None = Field(default=None, max_length=100)
    minimum_severity: str = "INFO"
    email_enabled: bool = False
    slack_enabled: bool = False
    teams_enabled: bool = False
    webhook_enabled: bool = False


class NotificationPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    enabled: bool | None = None
    source: str | None = Field(default=None, max_length=100)
    event_type: str | None = Field(default=None, max_length=100)
    minimum_severity: str | None = None
    email_enabled: bool | None = None
    slack_enabled: bool | None = None
    teams_enabled: bool | None = None
    webhook_enabled: bool | None = None


def serialize_policy(policy):
    return {
        "id": policy.id,
        "name": policy.name,
        "enabled": policy.enabled,
        "source": policy.source,
        "event_type": policy.event_type,
        "minimum_severity": policy.minimum_severity,
        "email_enabled": policy.email_enabled,
        "slack_enabled": policy.slack_enabled,
        "teams_enabled": policy.teams_enabled,
        "webhook_enabled": policy.webhook_enabled,
        "created_at": policy.created_at.isoformat() if policy.created_at else None,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }


def validate_severity(value: str) -> str:
    value = str(value or "INFO").upper().strip()

    if value not in SEVERITY_ORDER:
        raise HTTPException(
            status_code=400,
            detail="minimum_severity must be INFO, LOW, MEDIUM, HIGH, or CRITICAL.",
        )

    return value


@router.get("")
def list_notification_policies(
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    policies = (
        db.query(NotificationPolicy)
        .order_by(NotificationPolicy.created_at.desc())
        .all()
    )

    return {
        "count": len(policies),
        "policies": [serialize_policy(item) for item in policies],
    }


@router.post("")
def create_notification_policy(
    payload: NotificationPolicyCreate,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    name = payload.name.strip()

    if not name:
        raise HTTPException(status_code=400, detail="Policy name is required.")

    existing = (
        db.query(NotificationPolicy)
        .filter(NotificationPolicy.name == name)
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="A notification policy with this name already exists.",
        )

    policy = NotificationPolicy(
        name=name,
        enabled=payload.enabled,
        source=payload.source.strip() if payload.source else None,
        event_type=payload.event_type.strip() if payload.event_type else None,
        minimum_severity=validate_severity(payload.minimum_severity),
        email_enabled=payload.email_enabled,
        slack_enabled=payload.slack_enabled,
        teams_enabled=payload.teams_enabled,
        webhook_enabled=payload.webhook_enabled,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )

    db.add(policy)
    db.commit()
    db.refresh(policy)

    return serialize_policy(policy)


@router.put("/{policy_id}")
def update_notification_policy(
    policy_id: int,
    payload: NotificationPolicyUpdate,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    policy = (
        db.query(NotificationPolicy)
        .filter(NotificationPolicy.id == policy_id)
        .first()
    )

    if not policy:
        raise HTTPException(status_code=404, detail="Notification policy not found.")

    data = payload.model_dump(exclude_unset=True)

    if "name" in data:
        name = data["name"].strip()

        if not name:
            raise HTTPException(status_code=400, detail="Policy name is required.")

        duplicate = (
            db.query(NotificationPolicy)
            .filter(
                NotificationPolicy.name == name,
                NotificationPolicy.id != policy_id,
            )
            .first()
        )

        if duplicate:
            raise HTTPException(
                status_code=409,
                detail="A notification policy with this name already exists.",
            )

        data["name"] = name

    if "minimum_severity" in data:
        data["minimum_severity"] = validate_severity(
            data["minimum_severity"]
        )

    if "source" in data and data["source"]:
        data["source"] = data["source"].strip()

    if "event_type" in data and data["event_type"]:
        data["event_type"] = data["event_type"].strip()

    for key, value in data.items():
        setattr(policy, key, value)

    policy.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(policy)

    return serialize_policy(policy)


@router.delete("/{policy_id}")
def delete_notification_policy(
    policy_id: int,
    current_user=Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    policy = (
        db.query(NotificationPolicy)
        .filter(NotificationPolicy.id == policy_id)
        .first()
    )

    if not policy:
        raise HTTPException(status_code=404, detail="Notification policy not found.")

    db.delete(policy)
    db.commit()

    return {
        "message": "Notification policy deleted",
        "policy_id": policy_id,
    }
