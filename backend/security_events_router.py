from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models import SecurityEvent
from rbac import require_role


router = APIRouter(
    prefix="/security-events",
    tags=["SOC Security Events"],
)


def serialize_event(event):
    return {
        "id": event.id,
        "event_id": event.event_id,
        "timestamp": (
            event.timestamp.isoformat()
            if event.timestamp
            else None
        ),
        "source": event.source,
        "event_type": event.event_type,
        "severity": event.severity,
        "message": event.message,
        "target": event.target,
        "assessment_id": event.assessment_id,

        "mitre": {
            "technique_id": event.mitre_technique_id,
            "technique_name": event.mitre_technique_name,
            "is_subtechnique": (
                bool(event.mitre_technique_id)
                and "." in event.mitre_technique_id
            ),
            "parent_technique_id": (
                event.mitre_technique_id.split(".")[0]
                if (
                    event.mitre_technique_id
                    and "." in event.mitre_technique_id
                )
                else event.mitre_technique_id
            ),
            "tactic": event.mitre_tactic,
            "mapping_source": event.mitre_mapping_source,
            "confidence": event.mitre_confidence,
            "evidence": event.mitre_evidence,
        },

        # Alert lifecycle
        "alert_status": event.alert_status,
        "acknowledged_at": (
            event.acknowledged_at.isoformat()
            if event.acknowledged_at
            else None
        ),
        "resolved_at": (
            event.resolved_at.isoformat()
            if event.resolved_at
            else None
        ),

        "created_at": (
            event.created_at.isoformat()
            if event.created_at
            else None
        ),
    }


@router.get("")
def get_security_events(
    limit: int = Query(100, ge=1, le=500),
    severity: str | None = Query(None),
    source: str | None = Query(None),
    mitre_technique: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
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

    if mitre_technique:
        query = query.filter(
            SecurityEvent.mitre_technique_id
            == mitre_technique.upper()
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
    current_user=Depends(require_role(1)),
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
    current_user=Depends(require_role(1)),
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
    current_user=Depends(require_role(1)),
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
    current_user=Depends(require_role(1)),
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
    current_user=Depends(require_role(1)),
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
    current_user=Depends(require_role(1)),
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