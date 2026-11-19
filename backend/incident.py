import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import (
    Column, DateTime, ForeignKey, Integer, String, Text,
    UniqueConstraint, text,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine, get_db
from models import SecurityEvent, AlertResult
from rbac import require_role


# ==================================================
# INCIDENT CASE MODEL
# ==================================================

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    incident_id = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
    )

    security_event_id = Column(
        Integer,
        ForeignKey("security_events.id"),
        nullable=True,
        index=True,
    )

    source_event_id = Column(
        String(255),
        nullable=True,
        index=True,
    )

    title = Column(
        String(500),
        nullable=False,
    )

    description = Column(
        Text,
        nullable=True,
    )

    severity = Column(
        String(50),
        nullable=False,
        default="MEDIUM",
        index=True,
    )

    status = Column(
        String(30),
        nullable=False,
        default="OPEN",
        index=True,
    )

    assigned_to = Column(
        String(255),
        nullable=True,
        index=True,
    )

    investigation_notes = Column(
        Text,
        nullable=True,
    )

    resolution = Column(
        Text,
        nullable=True,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        index=True,
    )

    investigation_started_at = Column(
        DateTime,
        nullable=True,
    )

    contained_at = Column(
        DateTime,
        nullable=True,
    )

    resolved_at = Column(
        DateTime,
        nullable=True,
    )

    closed_at = Column(
        DateTime,
        nullable=True,
    )


class IncidentAlertLink(Base):
    __tablename__ = "incident_alert_links"

    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "alert_result_id",
            name="uq_incident_alert_link",
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(
        Integer,
        ForeignKey("incidents.id"),
        nullable=False,
        index=True,
    )

    alert_result_id = Column(
        Integer,
        ForeignKey("alert_results.id"),
        nullable=False,
        index=True,
    )

    created_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
    )


# ==================================================
# CREATE ONLY THE NEW INCIDENT TABLE
# ==================================================

Incident.__table__.create(
    bind=engine,
    checkfirst=True,
)

IncidentAlertLink.__table__.create(
    bind=engine,
    checkfirst=True,
)

# Ensure only one persistent incident exists per security event.
with engine.begin() as connection:
    connection.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        uq_incidents_security_event_id_not_null
        ON incidents (security_event_id)
        WHERE security_event_id IS NOT NULL
    """))


def create_incidents_for_event(event_payload):
    """
    Create one persistent incident for qualifying alerts
    belonging to a committed security event.

    Multiple qualifying alerts for the same event are linked
    to the same incident.
    """
    event_ref = event_payload.get("event_id")

    if not event_ref:
        return {"created": 0, "linked": 0, "incident_id": None}

    db = SessionLocal()

    try:
        event = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.event_id == event_ref)
            .with_for_update()
            .first()
        )

        if not event:
            return {"created": 0, "linked": 0, "incident_id": None}

        qualifying_alerts = (
            db.query(AlertResult)
            .filter(
                AlertResult.security_event_id == event.id,
                AlertResult.severity.in_(
                    ["ERROR", "HIGH", "CRITICAL"]
                ),
            )
            .order_by(AlertResult.id.asc())
            .all()
        )

        if not qualifying_alerts:
            return {"created": 0, "linked": 0, "incident_id": None}

        case = (
            db.query(Incident)
            .filter(Incident.security_event_id == event.id)
            .first()
        )

        created = 0

        if case is None:
            first_alert = qualifying_alerts[0]

            case = Incident(
                incident_id=f"INC-{event.id:06d}",
                security_event_id=event.id,
                source_event_id=event.event_id,
                title=f"{first_alert.alert_name}: {event.message}"[:500],
                description=(
                    f"Automatically created from alert "
                    f"{first_alert.alert_name}. "
                    f"Priority: {first_alert.priority}. "
                    f"Original event: {event.message}"
                ),
                severity=first_alert.severity,
                status="OPEN",
            )

            db.add(case)
            db.flush()
            created = 1

        linked = 0

        for alert in qualifying_alerts:
            existing_link = (
                db.query(IncidentAlertLink)
                .filter(
                    IncidentAlertLink.incident_id == case.id,
                    IncidentAlertLink.alert_result_id == alert.id,
                )
                .first()
            )

            if existing_link:
                continue

            db.add(
                IncidentAlertLink(
                    incident_id=case.id,
                    alert_result_id=alert.id,
                )
            )
            linked += 1

        db.commit()

        return {
            "created": created,
            "linked": linked,
            "incident_id": case.incident_id,
        }

    except IntegrityError:
        db.rollback()

        # Another worker may have created the incident concurrently.
        existing = (
            db.query(Incident)
            .filter(Incident.security_event_id.isnot(None))
            .filter(
                Incident.security_event_id
                == db.query(SecurityEvent.id)
                .filter(SecurityEvent.event_id == event_ref)
                .scalar_subquery()
            )
            .first()
        )

        if existing:
            return {
                "created": 0,
                "linked": 0,
                "incident_id": existing.incident_id,
            }

        raise

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


# ==================================================
# ROUTER
# ==================================================

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
    dependencies=[Depends(require_role(3))],
)


# ==================================================
# HELPERS
# ==================================================

def parse_raw_event(raw_event):
    if not raw_event:
        return None

    if isinstance(raw_event, dict):
        return raw_event

    try:
        return json.loads(raw_event)
    except (TypeError, json.JSONDecodeError):
        return raw_event


def extract_detection_context(raw_event):
    raw_event = parse_raw_event(raw_event)

    if not isinstance(raw_event, dict):
        return {
            "correlation": None,
            "detection": None,
        }

    return {
        "correlation": raw_event.get("correlation"),
        "detection": raw_event.get("detection"),
    }


def serialize_security_event_incident(event: SecurityEvent):
    raw_event = parse_raw_event(event.raw_event)
    context = extract_detection_context(event.raw_event)

    return {
        "incident_id": f"INC-{event.id:06d}",
        "source_event_id": event.event_id,
        "database_id": event.id,

        "title": event.message,
        "severity": event.severity,

        "status": event.alert_status or "OPEN",

        "timestamp": (
            event.timestamp.isoformat()
            if event.timestamp
            else None
        ),

        "source": event.source,
        "event_type": event.event_type,
        "target": event.target,

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

        "assessment_id": event.assessment_id,

        "mitre": {
            "technique_id": event.mitre_technique_id,
            "technique_name": event.mitre_technique_name,
            "tactic": event.mitre_tactic,
            "confidence": event.mitre_confidence,
            "mapping_source": event.mitre_mapping_source,
            "evidence": event.mitre_evidence,
        },

        "correlation": context["correlation"],
        "detection": context["detection"],

        "raw_event": raw_event,
    }


def serialize_case(case: Incident):
    return {
        "database_id": case.id,
        "incident_id": case.incident_id,
        "security_event_id": case.security_event_id,
        "source_event_id": case.source_event_id,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "assigned_to": case.assigned_to,
        "investigation_notes": case.investigation_notes,
        "resolution": case.resolution,
        "created_at": (
            case.created_at.isoformat()
            if case.created_at
            else None
        ),
        "updated_at": (
            case.updated_at.isoformat()
            if case.updated_at
            else None
        ),
        "investigation_started_at": (
            case.investigation_started_at.isoformat()
            if case.investigation_started_at
            else None
        ),
        "contained_at": (
            case.contained_at.isoformat()
            if case.contained_at
            else None
        ),
        "resolved_at": (
            case.resolved_at.isoformat()
            if case.resolved_at
            else None
        ),
        "closed_at": (
            case.closed_at.isoformat()
            if case.closed_at
            else None
        ),
    }


# ==================================================
# SECURITY-EVENT VIEW
# ==================================================

@router.get("/")
def get_incidents(
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Incident, SecurityEvent)
        .outerjoin(
            SecurityEvent,
            Incident.security_event_id == SecurityEvent.id,
        )
        .order_by(Incident.created_at.desc())
        .all()
    )

    incidents = []

    for case, event in rows:
        if event:
            item = serialize_security_event_incident(event)
        else:
            item = {
                "source": None,
                "event_type": None,
                "target": None,
                "timestamp": None,
                "assessment_id": None,
                "mitre": {
                    "technique_id": None,
                    "technique_name": None,
                    "tactic": None,
                    "confidence": None,
                    "mapping_source": None,
                    "evidence": None,
                },
                "correlation": None,
                "detection": None,
                "raw_event": None,
            }

        item.update({
            "incident_id": case.incident_id,
            "database_id": case.id,
            "security_event_id": case.security_event_id,
            "source_event_id": case.source_event_id,
            "title": case.title,
            "severity": case.severity,
            "status": case.status,
            "assigned_to": case.assigned_to,
            "created_at": (
                case.created_at.isoformat()
                if case.created_at else None
            ),
            "case": serialize_case(case),
        })

        if not item.get("timestamp"):
            item["timestamp"] = item["created_at"]

        incidents.append(item)

    return {
        "count": len(incidents),
        "incidents": incidents,
    }


# CREATE PERSISTENT INCIDENT CASE FROM SECURITY EVENT
# ==================================================

@router.post("/{incident_id}/case")
def create_incident_case(
    incident_id: str,
    db: Session = Depends(get_db),
):
    if not incident_id.startswith("INC-"):
        raise HTTPException(
            status_code=400,
            detail="Invalid incident ID.",
        )

    try:
        security_event_id = int(
            incident_id.replace(
                "INC-",
                "",
                1,
            )
        )
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid incident ID.",
        )

    event = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.id == security_event_id,
            SecurityEvent.mitre_technique_id.isnot(None),
            SecurityEvent.severity.in_(
                [
                    "ERROR",
                    "HIGH",
                    "CRITICAL",
                ]
            ),
        )
        .first()
    )

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Security event for this incident was not found.",
        )

    existing_case = (
        db.query(Incident)
        .filter(
            Incident.security_event_id == event.id
        )
        .first()
    )

    if existing_case:
        return {
            "created": False,
            "case": serialize_case(existing_case),
        }

    raw_event = parse_raw_event(event.raw_event)
    detection = None

    if isinstance(raw_event, dict):
        detection = raw_event.get("detection")

    detection_type = None

    if isinstance(detection, dict):
        detection_type = detection.get(
            "detection_type"
        )

    description = (
        f"Incident created from SOC security event "
        f"{event.event_id or event.id}."
    )

    if detection_type:
        description += (
            f" Detection type: {detection_type}."
        )

    case = Incident(
        incident_id=f"INC-{event.id:06d}",
        security_event_id=event.id,
        source_event_id=event.event_id,
        title=event.message,
        description=description,
        severity=event.severity,
        status="OPEN",
        assigned_to=None,
        investigation_notes=None,
        resolution=None,
        investigation_started_at=None,
        contained_at=None,
        resolved_at=None,
        closed_at=None,
    )

    db.add(case)
    db.commit()
    db.refresh(case)

    return {
        "created": True,
        "case": serialize_case(case),
    }


# ==================================================
# GET PERSISTENT INCIDENT CASE
# ==================================================

@router.get("/{incident_id}/case")
def get_incident_case(
    incident_id: str,
    db: Session = Depends(get_db),
):
    case = (
        db.query(Incident)
        .filter(
            Incident.incident_id == incident_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    return serialize_case(case)


# ==================================================
# START INCIDENT INVESTIGATION
# ==================================================

@router.patch("/{incident_id}/case/start")
def start_incident_investigation(
    incident_id: str,
    db: Session = Depends(get_db),
):
    case = (
        db.query(Incident)
        .filter(
            Incident.incident_id == incident_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    if case.status == "IN_PROGRESS":
        return {
            "started": False,
            "case": serialize_case(case),
        }

    if case.status in {
        "CONTAINED",
        "RESOLVED",
        "CLOSED",
    }:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Investigation cannot be started because the case "
                f"is already {case.status}."
            ),
        )

    now = datetime.utcnow()

    case.status = "IN_PROGRESS"
    case.investigation_started_at = (
        case.investigation_started_at or now
    )
    case.updated_at = now

    db.commit()
    db.refresh(case)

    return {
        "started": True,
        "case": serialize_case(case),
    }


# ==================================================
# CONTAIN INCIDENT
# ==================================================

@router.patch("/{incident_id}/case/contain")
def contain_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    case = (
        db.query(Incident)
        .filter(
            Incident.incident_id == incident_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    if case.status == "CONTAINED":
        return {
            "contained": False,
            "case": serialize_case(case),
        }

    if case.status != "IN_PROGRESS":
        raise HTTPException(
            status_code=409,
            detail=(
                f"Incident can only be contained when the case is "
                f"IN_PROGRESS. Current status: {case.status}."
            ),
        )

    now = datetime.utcnow()

    case.status = "CONTAINED"
    case.contained_at = case.contained_at or now
    case.updated_at = now

    db.commit()
    db.refresh(case)

    return {
        "contained": True,
        "case": serialize_case(case),
    }


# ==================================================
# ASSIGN INCIDENT CASE
# ==================================================

@router.patch("/{incident_id}/case/assign")
def assign_incident_case(
    incident_id: str,
    db: Session = Depends(get_db),
    assigned_to: str | None = None,
):
    case = (
        db.query(Incident)
        .filter(
            Incident.incident_id == incident_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    if case.status == "CLOSED":
        raise HTTPException(
            status_code=409,
            detail="Incident is already CLOSED and cannot be reassigned.",
        )

    analyst = (assigned_to or "").strip()

    if not analyst:
        raise HTTPException(
            status_code=400,
            detail="Assigned analyst is required.",
        )

    now = datetime.utcnow()
    case.assigned_to = analyst
    case.updated_at = now

    db.commit()
    db.refresh(case)

    return {
        "assigned": True,
        "case": serialize_case(case),
    }


# ==================================================
# RESOLVE INCIDENT
# ==================================================

@router.patch("/{incident_id}/case/resolve")
def resolve_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    resolution: str | None = None,
):
    case = (
        db.query(Incident)
        .filter(
            Incident.incident_id == incident_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    if case.status == "RESOLVED":
        return {
            "resolved": False,
            "case": serialize_case(case),
        }

    if case.status == "CLOSED":
        raise HTTPException(
            status_code=409,
            detail="Incident is already CLOSED.",
        )

    if case.status != "CONTAINED":
        raise HTTPException(
            status_code=409,
            detail=(
                "Incident must be CONTAINED before it can be RESOLVED."
            ),
        )

    resolution_text = (resolution or "").strip()

    if not resolution_text:
        raise HTTPException(
            status_code=400,
            detail="Resolution summary is required to resolve the incident.",
        )

    now = datetime.utcnow()

    case.status = "RESOLVED"
    case.resolution = resolution_text
    case.resolved_at = now
    case.updated_at = now

    db.commit()
    db.refresh(case)

    return {
        "resolved": True,
        "case": serialize_case(case),
    }


# ==================================================
# CLOSE INCIDENT
# ==================================================

@router.patch("/{incident_id}/case/close")
def close_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    case = (
        db.query(Incident)
        .filter(
            Incident.incident_id == incident_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    if case.status == "CLOSED":
        return {
            "closed": False,
            "case": serialize_case(case),
        }

    if case.status != "RESOLVED":
        raise HTTPException(
            status_code=409,
            detail=(
                "Incident must be RESOLVED before it can be CLOSED."
            ),
        )

    now = datetime.utcnow()

    case.status = "CLOSED"
    case.closed_at = now
    case.updated_at = now

    db.commit()
    db.refresh(case)

    return {
        "closed": True,
        "case": serialize_case(case),
    }


# ==================================================
# UPDATE INCIDENT INVESTIGATION NOTES
# ==================================================

@router.patch("/{incident_id}/case/notes")
def update_incident_notes(
    incident_id: str,
    db: Session = Depends(get_db),
    notes: str | None = None,
):
    case = (
        db.query(Incident)
        .filter(
            Incident.incident_id == incident_id
        )
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    notes_text = (notes or "").strip()

    if not notes_text:
        raise HTTPException(
            status_code=400,
            detail="Investigation notes cannot be empty.",
        )

    case.investigation_notes = notes_text
    case.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(case)

    return {
        "updated": True,
        "case": serialize_case(case),
    }


# ==================================================
# SECURITY-EVENT INCIDENT DETAIL
# ==================================================

@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
):
    case = (
        db.query(Incident)
        .filter(Incident.incident_id == incident_id)
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    event = None

    if case.security_event_id is not None:
        event = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.id == case.security_event_id)
            .first()
        )

    if event:
        response = serialize_security_event_incident(event)
    else:
        response = {
            "source": None,
            "event_type": None,
            "target": None,
            "timestamp": None,
            "assessment_id": None,
            "mitre": {
                "technique_id": None,
                "technique_name": None,
                "tactic": None,
                "confidence": None,
                "mapping_source": None,
                "evidence": None,
            },
            "correlation": None,
            "detection": None,
            "raw_event": None,
        }

    response.update({
        "incident_id": case.incident_id,
        "database_id": case.id,
        "security_event_id": case.security_event_id,
        "source_event_id": case.source_event_id,
        "title": case.title,
        "severity": case.severity,
        "status": case.status,
        "assigned_to": case.assigned_to,
        "created_at": (
            case.created_at.isoformat()
            if case.created_at else None
        ),
        "case": serialize_case(case),
    })

    if not response.get("timestamp"):
        response["timestamp"] = response["created_at"]

    return response

