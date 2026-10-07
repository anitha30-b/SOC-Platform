import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import NotificationChannelConfig
from rbac import require_role


router = APIRouter(
    prefix="/admin/notification-channels",
    tags=["Admin Notification Channels"],
)


ALLOWED_CHANNELS = {"email", "slack", "teams", "webhook"}


class NotificationChannelUpdate(BaseModel):
    enabled: bool | None = None
    endpoint: str | None = None
    username: str | None = None
    secret: str | None = None
    configuration: dict | None = None


def serialize_channel(channel: NotificationChannelConfig):
    return {
        "id": channel.id,
        "channel": channel.channel,
        "enabled": channel.enabled,
        "endpoint": channel.endpoint,
        "username": channel.username,
        "has_secret": bool(channel.secret),
        "configuration": (
            json.loads(channel.configuration)
            if channel.configuration
            else {}
        ),
        "created_at": (
            channel.created_at.isoformat()
            if channel.created_at
            else None
        ),
        "updated_at": (
            channel.updated_at.isoformat()
            if channel.updated_at
            else None
        ),
    }


@router.get("")
def get_notification_channels(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    channels = (
        db.query(NotificationChannelConfig)
        .order_by(NotificationChannelConfig.channel.asc())
        .all()
    )

    return {
        "count": len(channels),
        "channels": [
            serialize_channel(channel)
            for channel in channels
        ],
    }


@router.get("/{channel}")
def get_notification_channel(
    channel: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    channel = channel.strip().lower()

    if channel not in ALLOWED_CHANNELS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported notification channel: {channel}",
        )

    config = (
        db.query(NotificationChannelConfig)
        .filter(NotificationChannelConfig.channel == channel)
        .first()
    )

    if not config:
        return {
            "channel": channel,
            "configured": False,
            "enabled": False,
            "endpoint": None,
            "username": None,
            "has_secret": False,
            "configuration": {},
        }

    return {
        "configured": True,
        **serialize_channel(config),
    }


@router.put("/{channel}")
def update_notification_channel(
    channel: str,
    payload: NotificationChannelUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    channel = channel.strip().lower()

    if channel not in ALLOWED_CHANNELS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported notification channel: {channel}",
        )

    config = (
        db.query(NotificationChannelConfig)
        .filter(NotificationChannelConfig.channel == channel)
        .first()
    )

    if not config:
        config = NotificationChannelConfig(
            channel=channel,
            enabled=False,
        )
        db.add(config)

    if payload.enabled is not None:
        config.enabled = payload.enabled

    if payload.endpoint is not None:
        config.endpoint = payload.endpoint.strip() or None

    if payload.username is not None:
        config.username = payload.username.strip() or None

    if payload.secret is not None:
        config.secret = payload.secret

    if payload.configuration is not None:
        config.configuration = json.dumps(
            payload.configuration
        )

    config.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(config)

    return serialize_channel(config)


@router.delete("/{channel}")
def delete_notification_channel(
    channel: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    channel = channel.strip().lower()

    config = (
        db.query(NotificationChannelConfig)
        .filter(NotificationChannelConfig.channel == channel)
        .first()
    )

    if not config:
        raise HTTPException(
            status_code=404,
            detail="Notification channel configuration not found",
        )

    db.delete(config)
    db.commit()

    return {
        "message": "Notification channel configuration deleted",
        "channel": channel,
    }
