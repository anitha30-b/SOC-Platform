from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import PlatformConfiguration, AuditLog, User
from rbac import require_role

router = APIRouter(
    prefix="/admin/platform-config",
    tags=["Platform Configuration"],
)


class PlatformConfigUpdate(BaseModel):
    session_timeout_minutes: int = Field(ge=1, le=1440)
    password_min_length: int = Field(ge=6, le=128)
    password_require_uppercase: bool
    password_require_lowercase: bool
    password_require_number: bool
    password_require_special: bool
    max_failed_login_attempts: int = Field(ge=1, le=100)
    account_lockout_minutes: int = Field(ge=1, le=1440)


def serialize_config(item):
    return {
        "id": item.id,
        "session_timeout_minutes": item.session_timeout_minutes,
        "password_min_length": item.password_min_length,
        "password_require_uppercase": item.password_require_uppercase,
        "password_require_lowercase": item.password_require_lowercase,
        "password_require_number": item.password_require_number,
        "password_require_special": item.password_require_special,
        "max_failed_login_attempts": item.max_failed_login_attempts,
        "account_lockout_minutes": item.account_lockout_minutes,
        "created_by": item.created_by,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "updated_at": item.updated_at.isoformat() if item.updated_at else None,
    }


def get_or_create_config(db):
    item = db.query(PlatformConfiguration).order_by(
        PlatformConfiguration.id.asc()
    ).first()

    if item is None:
        item = PlatformConfiguration()
        db.add(item)
        db.commit()
        db.refresh(item)

    return item


@router.get("")
def get_platform_config(
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    item = get_or_create_config(db)
    return serialize_config(item)


@router.put("")
def update_platform_config(
    payload: PlatformConfigUpdate,
    request: Request,
    current_user: User = Depends(require_role(3)),
    db: Session = Depends(get_db),
):
    item = get_or_create_config(db)
    changes = payload.model_dump()

    before = {
        key: getattr(item, key)
        for key in changes
    }

    for key, value in changes.items():
        setattr(item, key, value)

    item.created_by = current_user.username
    item.updated_at = datetime.utcnow()

    db.add(
        AuditLog(
            user_id=current_user.id,
            username=current_user.username,
            action="Platform configuration updated",
            module="Platform Configuration",
            ip_address=request.client.host if request.client else None,
            status="SUCCESS",
            details=f"Before: {before}; After: {changes}",
        )
    )

    try:
        db.commit()
        db.refresh(item)
        return {
            "message": "Platform configuration updated successfully.",
            "configuration": serialize_config(item),
        }
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not update platform configuration.",
        )
