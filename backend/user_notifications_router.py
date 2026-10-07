from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from database import get_db
from models import Notification
from rbac import require_role


router = APIRouter(
    prefix="/notifications",
    tags=["User Notifications"],
)


def serialize_notification(notification):
    return {
        "id": notification.id,
        "notification_id": notification.notification_id,
        "event_id": notification.event_id,
        "assessment_id": notification.assessment_id,
        "source": notification.source,
        "event_type": notification.event_type,
        "severity": notification.severity,
        "title": notification.title,
        "message": notification.message,
        "target": notification.target,
        "is_read": notification.is_read,
        "read_at": (
            notification.read_at.isoformat()
            if notification.read_at
            else None
        ),
        "created_at": (
            notification.created_at.isoformat()
            if notification.created_at
            else None
        ),
    }


@router.get("")
def get_user_notifications(
    limit: int = Query(100, ge=1, le=500),
    unread_only: bool = Query(False),
    severity: str | None = Query(None),
    source: str | None = Query(None),
    assessment_id: int | None = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    query = db.query(Notification).filter(
        Notification.user_id == current_user.id
    )

    if unread_only:
        query = query.filter(Notification.is_read.is_(False))

    if severity:
        query = query.filter(
            Notification.severity == severity.upper()
        )

    if source:
        query = query.filter(
            Notification.source == source
        )

    if assessment_id is not None:
        query = query.filter(
            Notification.assessment_id == assessment_id
        )

    notifications = (
        query
        .order_by(Notification.created_at.desc())
        .limit(limit)
        .all()
    )

    return {
        "count": len(notifications),
        "notifications": [
            serialize_notification(item)
            for item in notifications
        ],
    }


@router.get("/unread-count")
def get_user_unread_count(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    count = (
        db.query(Notification)
        .filter(
            Notification.user_id == current_user.id,
            Notification.is_read.is_(False),
        )
        .count()
    )

    return {
        "unread_count": count,
    }


@router.patch("/{notification_id}/read")
def mark_user_notification_read(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    notification = (
        db.query(Notification)
        .filter(
            Notification.notification_id == notification_id,
            Notification.user_id == current_user.id,
        )
        .first()
    )

    if not notification:
        raise HTTPException(
            status_code=404,
            detail="Notification not found",
        )

    notification.is_read = True
    notification.read_at = datetime.utcnow()

    db.commit()
    db.refresh(notification)

    return serialize_notification(notification)


@router.patch("/{notification_id}/unread")
def mark_user_notification_unread(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    notification = (
        db.query(Notification)
        .filter(
            Notification.notification_id == notification_id,
            Notification.user_id == current_user.id,
        )
        .first()
    )

    if not notification:
        raise HTTPException(
            status_code=404,
            detail="Notification not found",
        )

    notification.is_read = False
    notification.read_at = None

    db.commit()
    db.refresh(notification)

    return serialize_notification(notification)


@router.patch("/read-all")
def mark_all_user_notifications_read(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    updated = (
        db.query(Notification)
        .filter(
            Notification.user_id == current_user.id,
            Notification.is_read.is_(False),
        )
        .update(
            {
                Notification.is_read: True,
                Notification.read_at: datetime.utcnow(),
            },
            synchronize_session=False,
        )
    )

    db.commit()

    return {
        "updated": updated,
        "message": "All notifications marked as read",
    }


@router.delete("/{notification_id}")
def delete_user_notification(
    notification_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    notification = (
        db.query(Notification)
        .filter(
            Notification.notification_id == notification_id,
            Notification.user_id == current_user.id,
        )
        .first()
    )

    if not notification:
        raise HTTPException(
            status_code=404,
            detail="Notification not found",
        )

    db.delete(notification)
    db.commit()

    return {
        "message": "Notification deleted",
        "notification_id": notification_id,
    }
