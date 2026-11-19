import json
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models import NotificationChannelConfig
from rbac import require_role
from notification_security import encrypt_notification_secret


router = APIRouter(
    prefix="/admin/notification-channels",
    tags=["Admin Notification Channels"],
)


ALLOWED_CHANNELS = {"email", "slack", "teams", "webhook"}


def validate_slack_webhook_url(value: str):
    try:
        parsed = urlparse(value)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == "hooks.slack.com"
            and parsed.path.startswith("/services/")
            and not parsed.username
            and not parsed.password
        )
    except ValueError:
        valid = False

    if not valid:
        raise HTTPException(
            status_code=400,
            detail="Enter a valid HTTPS Slack Incoming Webhook URL.",
        )

    return value


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
        "endpoint": None if channel.channel == "slack" else channel.endpoint,
        "username": channel.username,
        "has_secret": bool(channel.secret or (channel.channel == "slack" and channel.endpoint)),
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

    if channel == "slack":
        if payload.endpoint is not None and payload.endpoint.strip():
            webhook_url = validate_slack_webhook_url(
                payload.endpoint.strip()
            )
            config.secret = encrypt_notification_secret(webhook_url)
            config.endpoint = None
        elif config.endpoint:
            # Securely migrate any older plaintext Slack endpoint.
            config.secret = encrypt_notification_secret(
                validate_slack_webhook_url(config.endpoint.strip())
            )
            config.endpoint = None
    else:
        if payload.endpoint is not None:
            config.endpoint = payload.endpoint.strip() or None

        if payload.secret is not None:
            config.secret = (
                encrypt_notification_secret(payload.secret)
                if channel == "email"
                else payload.secret
            )

    if payload.username is not None:
        config.username = payload.username.strip() or None

    if payload.configuration is not None:
        config.configuration = json.dumps(
            payload.configuration
        )

    config.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(config)

    return serialize_channel(config)


@router.post("/slack/test")
def test_slack_notification_endpoint(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    from types import SimpleNamespace
    from notification_service import send_slack_notification

    config = (
        db.query(NotificationChannelConfig)
        .filter(NotificationChannelConfig.channel == "slack")
        .first()
    )

    if not config or not (config.secret or config.endpoint):
        raise HTTPException(
            status_code=400,
            detail="Save a Slack webhook URL before testing the integration.",
        )

    test_notification = SimpleNamespace(
        title="SOC Platform Slack Test",
        message="Your SOC Platform Slack integration is working.",
        severity="INFO",
        source="SOC Platform",
        event_type="integration_test",
        target=None,
        notification_id="NTF-SLACK-TEST",
    )

    try:
        send_slack_notification(config, test_notification)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Slack test delivery failed. Verify the saved webhook URL and try again.",
        ) from exc

    return {"message": "Slack test notification sent successfully."}


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
