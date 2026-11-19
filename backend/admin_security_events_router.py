import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from database import get_db
from models import SecurityEvent
from rbac import get_current_user


router = APIRouter(
    prefix="/admin/security-events",
    tags=["SOC Security Events"],
)




def require_security_event_access(
    current_user=Depends(get_current_user),
):
    """
    Global SOC security events are restricted to Analysts and Admins.
    Client access must be scoped separately to client-owned data.
    """
    if current_user.role_id not in (2, 3):
        raise HTTPException(
            status_code=403,
            detail="Analyst or Admin access required.",
        )
    return current_user

from security_events_router import serialize_event

@router.get("")
def get_security_events(
    limit: int = Query(100, ge=1, le=500),
    severity: str | None = Query(None),
    source: str | None = Query(None),
    event_type: list[str] | None = Query(None),
    mitre_technique: str | None = Query(None),
    search: str | None = Query(None, max_length=200),
    db: Session = Depends(get_db),
    current_user=Depends(require_security_event_access),
):
    query = db.query(SecurityEvent)

    if severity:
        query = query.filter(
            SecurityEvent.severity == severity.upper()
        )

    if source:
        query = query.filter(
            SecurityEvent.source == source
        )

    if event_type:
        normalized_event_types = [
            value.strip().lower()
            for value in event_type
            if value and value.strip()
        ]
        if normalized_event_types:
            query = query.filter(
                SecurityEvent.event_type.in_(normalized_event_types)
            )

    if mitre_technique:
        query = query.filter(
            SecurityEvent.mitre_technique_id
            == mitre_technique.upper()
        )

    if search and search.strip():
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                SecurityEvent.source.ilike(pattern),
                SecurityEvent.event_type.ilike(pattern),
                SecurityEvent.message.ilike(pattern),
                SecurityEvent.target.ilike(pattern),
                SecurityEvent.mitre_technique_id.ilike(pattern),
                SecurityEvent.mitre_technique_name.ilike(pattern),
                SecurityEvent.mitre_tactic.ilike(pattern),
            )
        )

    events = (
        query
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
        .all()
    )

    return [
        serialize_event(event)
        for event in events
    ]


@router.get("/stats/techniques")
def get_mitre_technique_stats(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(require_security_event_access),
):
    rows = (
        db.query(
            SecurityEvent.mitre_technique_id,
            SecurityEvent.mitre_technique_name,
            func.count(SecurityEvent.id).label(
                "event_count"
            ),
        )
        .filter(
            SecurityEvent.mitre_technique_id.isnot(None)
        )
        .group_by(
            SecurityEvent.mitre_technique_id,
            SecurityEvent.mitre_technique_name,
        )
        .order_by(
            func.count(SecurityEvent.id).desc()
        )
        .limit(limit)
        .all()
    )

    return {
        "count": len(rows),
        "techniques": [
            {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "event_count": event_count,
            }
            for (
                technique_id,
                technique_name,
                event_count,
            ) in rows
        ],
    }


@router.get("/stats/tactics")
def get_mitre_tactic_stats(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(require_security_event_access),
):
    rows = (
        db.query(
            SecurityEvent.mitre_tactic,
            func.count(SecurityEvent.id).label(
                "event_count"
            ),
        )
        .filter(
            SecurityEvent.mitre_technique_id.isnot(None),
            SecurityEvent.mitre_tactic.isnot(None),
        )
        .group_by(
            SecurityEvent.mitre_tactic,
        )
        .order_by(
            func.count(SecurityEvent.id).desc()
        )
        .limit(limit)
        .all()
    )

    return {
        "count": len(rows),
        "tactics": [
            {
                "tactic": tactic,
                "event_count": event_count,
            }
            for tactic, event_count in rows
        ],
    }


@router.get("/stats/recent")
def get_recent_mitre_events(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(require_security_event_access),
):
    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.mitre_technique_id.isnot(None)
        )
        .order_by(
            SecurityEvent.timestamp.desc()
        )
        .limit(limit)
        .all()
    )

    return {
        "count": len(events),
        "events": [
            serialize_event(event)
            for event in events
        ],
    }


@router.get("/stats/active-alerts")
def get_active_mitre_alerts(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user=Depends(require_security_event_access),
):
    events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.mitre_technique_id.isnot(None),
            SecurityEvent.severity.in_(
                ["ERROR", "HIGH", "CRITICAL"]
            ),
            SecurityEvent.alert_status == "ACTIVE",
        )
        .order_by(
            SecurityEvent.timestamp.desc()
        )
        .limit(limit)
        .all()
    )

    return {
        "count": len(events),
        "alerts": [
            serialize_event(event)
            for event in events
        ],
    }


@router.patch("/{event_id}/acknowledge")
def acknowledge_security_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_security_event_access),
):
    event = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_id == event_id
        )
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Security event not found.",
        )

    if event.alert_status != "ACTIVE":
        raise HTTPException(
            status_code=400,
            detail=(
                "Only ACTIVE alerts can be acknowledged."
            ),
        )

    event.alert_status = "ACKNOWLEDGED"
    event.acknowledged_at = datetime.utcnow()

    db.commit()
    db.refresh(event)

    return {
        "message": "Security alert acknowledged.",
        "alert": serialize_event(event),
    }


@router.patch("/{event_id}/resolve")
def resolve_security_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_security_event_access),
):
    event = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.event_id == event_id
        )
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Security event not found.",
        )

    if event.alert_status != "ACKNOWLEDGED":
        raise HTTPException(
            status_code=400,
            detail=(
                "Only ACKNOWLEDGED alerts can be resolved."
            ),
        )

    event.alert_status = "RESOLVED"
    event.resolved_at = datetime.utcnow()

    db.commit()
    db.refresh(event)

    return {
        "message": "Security alert resolved.",
        "alert": serialize_event(event),
    }