from sqlalchemy import UniqueConstraint
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func, cast
import json
from models import User
from pydantic import BaseModel, Field
from sqlalchemy import or_
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Session

from database import Base, SessionLocal, engine, get_db
from models import SecurityEvent, AlertResult
from rbac import require_role
from security_event_scope import owned_security_event_filter


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


# ==================================================
# CREATE ONLY THE NEW INCIDENT TABLE
# ==================================================

# Schema creation is owned by schema_initialization, after all models are registered.


# ==================================================
# ROUTER
# ==================================================

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)



@router.get("/eligible-assignees")
def get_eligible_incident_assignees(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    query = db.query(User).filter(User.role_id == 1)
    if current_user.client_id is not None:
        query = query.filter(User.client_id == current_user.client_id)
    else:
        query = query.filter(User.id == current_user.id)

    return {
        "assignees": [
            {"username": user.username}
            for user in query.order_by(User.username.asc()).all()
        ]
    }


def _owned_incident_case_query(db, current_user):
    """Restrict incident cases to explicitly owned security events."""
    return (
        db.query(Incident)
        .join(SecurityEvent, Incident.security_event_id == SecurityEvent.id)
        .filter(owned_security_event_filter(db, current_user))
    )


# ==================================================
# HELPERS
# ==================================================


def _incident_utc_response(payload):
    """Format stored UTC timestamps without changing raw evidence."""
    fields = {
        "timestamp", "created_at", "updated_at", "acknowledged_at",
        "investigation_started_at", "contained_at", "resolved_at", "closed_at",
    }

    def record(item):
        result = dict(item)
        for field in fields:
            value = result.get(field)
            if isinstance(value, str) and value:
                parsed = datetime.fromisoformat(value)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                result[field] = parsed.astimezone(timezone.utc).isoformat()
        if isinstance(result.get("case"), dict):
            result["case"] = record(result["case"])
        return result

    if "incidents" in payload:
        return {**payload, "incidents": [
            record(item) for item in payload["incidents"]
        ]}
    return record(payload)



# Server-generated history, separate from client-submitted audit messages.
class IncidentHistory(Base):
    __tablename__ = "incident_history"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(
        String(100),
        ForeignKey("incidents.incident_id"),
        nullable=False,
        index=True,
    )
    actor_user_id = Column(
        Integer, ForeignKey("users.id"), nullable=False, index=True
    )
    actor_username = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    case_status = Column(String(30), nullable=False)
    assigned_to = Column(String(255), nullable=True)
    created_at = Column(
        DateTime, nullable=False, default=datetime.utcnow, index=True
    )


# Schema creation is owned by schema_initialization, after all models are registered.


def _record_incident_history(db, case, current_user, action):
    # No independent commit: history and case succeed or fail together.
    db.add(IncidentHistory(
        incident_id=case.incident_id,
        actor_user_id=current_user.id,
        actor_username=current_user.username,
        action=action,
        case_status=case.status,
        assigned_to=case.assigned_to,
        created_at=datetime.utcnow(),
    ))


@router.get("/{incident_id}/history")
def get_incident_history(
    incident_id: str,
    before_id: int | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    case = (
        _owned_incident_case_query(db, current_user)
        .filter(Incident.incident_id == incident_id)
        .first()
    )
    if not case:
        raise HTTPException(status_code=404, detail="Incident case not found.")

    limit = min(max(limit, 1), 200)
    query = db.query(IncidentHistory).filter(
        IncidentHistory.incident_id == case.incident_id
    )
    if before_id is not None:
        query = query.filter(IncidentHistory.id < before_id)

    rows = query.order_by(IncidentHistory.id.desc()).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    return {
        "incident_id": case.incident_id,
        "history": [
            {
                "id": row.id,
                "actor_username": row.actor_username,
                "action": row.action,
                "case_status": row.case_status,
                "assigned_to": row.assigned_to,
                "created_at": row.created_at.replace(
                    tzinfo=timezone.utc
                ).isoformat(),
            }
            for row in rows
        ],
        "next_before_id": rows[-1].id if has_more else None,
    }



class IncidentNotesRequest(BaseModel):
    notes: str = Field(min_length=1, max_length=50000)


class IncidentResolutionRequest(BaseModel):
    resolution: str = Field(min_length=1, max_length=20000)


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
    utc_timestamps: bool = False,
    include_unmapped_network: bool = False,
    include_case: bool = False,
    compact: bool = False,
    page_size: int | None = None,
    offset: int = 0,
    search: str = "",
    severity: str = "ALL",
    status: str = "ALL",
    incident_view: str = "all",
    include_summary: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    if offset < 0:
        raise HTTPException(status_code=400, detail="Offset cannot be negative.")
    if page_size is not None and not 1 <= page_size <= 200:
        raise HTTPException(
            status_code=400,
            detail="Page size must be between 1 and 200.",
        )
    if page_size is None and offset:
        raise HTTPException(
            status_code=400,
            detail="Offset requires page_size.",
        )

    query = (
        db.query(SecurityEvent)
        .filter(
            owned_security_event_filter(db, current_user),
            or_(
                SecurityEvent.mitre_technique_id.isnot(None),
                (
                    (SecurityEvent.source == "tshark-siem")
                    & (SecurityEvent.event_type == "network_detection")
                    if include_unmapped_network
                    else False
                ),
            ),
            SecurityEvent.severity.in_(
                [
                    "ERROR",
                    "HIGH",
                    "CRITICAL",
                ]
            ),
        )
    )

    allowed_views = {
        "all", "active", "critical", "closed",
        "investigation", "cases", "assignments",
    }
    if incident_view not in allowed_views:
        raise HTTPException(status_code=400, detail="Invalid incident view.")
    if len(search) > 200:
        raise HTTPException(status_code=400, detail="Search is limited to 200 characters.")

    severity = severity.strip().upper()
    status = status.strip().upper()
    summary = None

    if include_summary or search.strip() or severity != "ALL" or status != "ALL" or incident_view != "all":
        # Select the first saved case per event, matching existing serialization.
        first_case_id = (
            db.query(func.min(Incident.id))
            .filter(Incident.security_event_id == SecurityEvent.id)
            .correlate(SecurityEvent)
            .scalar_subquery()
        )
        query = query.outerjoin(Incident, Incident.id == first_case_id)
        effective_status = func.upper(func.coalesce(
            Incident.status, SecurityEvent.alert_status, "OPEN"
        ))

        if include_summary:
            summary = {"Total": 0, "Active": 0, "Critical": 0, "Closed": 0}
            groups = (
                query.with_entities(
                    effective_status,
                    func.upper(SecurityEvent.severity),
                    func.count(SecurityEvent.id),
                )
                .group_by(effective_status, func.upper(SecurityEvent.severity))
                .all()
            )
            for state, level, count in groups:
                summary["Total"] += count
                if state not in {"RESOLVED", "CLOSED"}:
                    summary["Active"] += count
                if level == "CRITICAL":
                    summary["Critical"] += count
                if state == "CLOSED":
                    summary["Closed"] += count

        if incident_view == "active":
            query = query.filter(effective_status.notin_(["RESOLVED", "CLOSED"]))
        elif incident_view == "critical":
            query = query.filter(func.upper(SecurityEvent.severity) == "CRITICAL")
        elif incident_view == "closed":
            query = query.filter(effective_status == "CLOSED")
        elif incident_view == "investigation":
            query = query.filter(
                Incident.id.isnot(None), effective_status == "IN_PROGRESS"
            )
        elif incident_view in {"cases", "assignments"}:
            query = query.filter(Incident.id.isnot(None))

        if severity != "ALL":
            query = query.filter(func.upper(SecurityEvent.severity) == severity)
        if status != "ALL":
            query = query.filter(effective_status == status)

        term = search.strip().lower()
        if term:
            fields = [
                SecurityEvent.message, SecurityEvent.source,
                SecurityEvent.target, SecurityEvent.event_type,
                SecurityEvent.mitre_technique_id, Incident.assigned_to,
                # Retain IP searching in stored detection evidence.
                cast(SecurityEvent.raw_event, String),
            ]
            conditions = [
                func.lower(field).contains(term, autoescape=True)
                for field in fields
            ]
            if term.startswith("inc-") and term[4:].isdigit():
                conditions.append(SecurityEvent.id == int(term[4:]))
            query = query.filter(or_(*conditions))

    total = query.count() if page_size is not None else None
    query = query.order_by(
        SecurityEvent.timestamp.desc(),
        SecurityEvent.id.desc(),
    )
    if page_size is not None:
        query = query.offset(offset).limit(page_size)
    events = query.all()

    incidents = [
        serialize_security_event_incident(event)
        for event in events
    ]

    if include_case and events:
        event_ids = [event.id for event in events]
        cases = (
            _owned_incident_case_query(db, current_user)
            .filter(Incident.security_event_id.in_(event_ids))
            .order_by(Incident.id.asc())
            .all()
        )
        cases_by_event = {}
        for case in cases:
            cases_by_event.setdefault(case.security_event_id, case)

        for item in incidents:
            case = cases_by_event.get(item["database_id"])
            item["case"] = serialize_case(case) if case else None

    if compact:
        for item in incidents:
            for key in ("raw_event", "correlation", "detection"):
                item.pop(key, None)

            if isinstance(item.get("mitre"), dict):
                item["mitre"] = {
                    key: value
                    for key, value in item["mitre"].items()
                    if key != "evidence"
                }

            if isinstance(item.get("case"), dict):
                item["case"] = {
                    key: value
                    for key, value in item["case"].items()
                    if key not in {
                        "description", "investigation_notes", "resolution"
                    }
                }

    response = {
        "count": len(incidents),
        "incidents": incidents,
    }
    if include_summary:
        response["summary"] = summary
    if page_size is not None:
        response.update({
            "total": total,
            "offset": offset,
            "page_size": page_size,
            "next_offset": (
                offset + len(incidents)
                if offset + len(incidents) < total
                else None
            ),
        })
    return _incident_utc_response(response) if utc_timestamps else response


# ==================================================
# CREATE PERSISTENT INCIDENT CASE FROM SECURITY EVENT
# ==================================================

@router.post("/{incident_id}/case")
def create_incident_case(
    incident_id: str,
    include_unmapped_network: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
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
            owned_security_event_filter(db, current_user),
            SecurityEvent.id == security_event_id,
            or_(
                SecurityEvent.mitre_technique_id.isnot(None),
                (
                    (SecurityEvent.source == "tshark-siem")
                    & (SecurityEvent.event_type == "network_detection")
                    if include_unmapped_network
                    else False
                ),
            ),
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
    _record_incident_history(db, case, current_user, "CASE_CREATED")
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
    current_user=Depends(require_role(1)),
):
    case = (
        _owned_incident_case_query(db, current_user)
        .filter(Incident.incident_id == incident_id)
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
    current_user=Depends(require_role(1)),
):
    case = (
        _owned_incident_case_query(db, current_user)
        .filter(Incident.incident_id == incident_id)
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

    _record_incident_history(db, case, current_user, "INVESTIGATION_STARTED")
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
    current_user=Depends(require_role(1)),
):
    case = (
        _owned_incident_case_query(db, current_user)
        .filter(Incident.incident_id == incident_id)
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

    _record_incident_history(db, case, current_user, "MARKED_CONTAINED")
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
    current_user=Depends(require_role(1)),
):
    case = (
        _owned_incident_case_query(db, current_user)
        .filter(Incident.incident_id == incident_id)
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

    candidates = db.query(User).filter(
        User.username == analyst,
        User.role_id == 1,
    )
    if current_user.client_id is not None:
        candidates = candidates.filter(
            User.client_id == current_user.client_id
        )
    else:
        candidates = candidates.filter(User.id == current_user.id)

    assignee = candidates.first()
    if assignee is None:
        raise HTTPException(
            status_code=400,
            detail="Select an eligible account within your client scope.",
        )

    if case.assigned_to == assignee.username:
        return {
            "assigned": False,
            "case": serialize_case(case),
        }

    now = datetime.utcnow()
    case.assigned_to = assignee.username
    case.updated_at = now

    _record_incident_history(db, case, current_user, "ANALYST_ASSIGNED")
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
    payload: IncidentResolutionRequest | None = None,
    current_user=Depends(require_role(1)),
):
    case = (
        _owned_incident_case_query(db, current_user)
        .filter(Incident.incident_id == incident_id)
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

    resolution_text = (
        payload.resolution if payload is not None else resolution or ""
    ).strip()

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

    _record_incident_history(db, case, current_user, "CASE_RESOLVED")
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
    current_user=Depends(require_role(1)),
):
    case = (
        _owned_incident_case_query(db, current_user)
        .filter(Incident.incident_id == incident_id)
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

    _record_incident_history(db, case, current_user, "CASE_CLOSED")
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
    payload: IncidentNotesRequest | None = None,
    current_user=Depends(require_role(1)),
):
    case = (
        _owned_incident_case_query(db, current_user)
        .filter(Incident.incident_id == incident_id)
        .first()
    )

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Persistent incident case not found.",
        )

    notes_text = (
        payload.notes if payload is not None else notes or ""
    ).strip()

    if not notes_text:
        raise HTTPException(
            status_code=400,
            detail="Investigation notes cannot be empty.",
        )

    case.investigation_notes = notes_text
    case.updated_at = datetime.utcnow()

    _record_incident_history(db, case, current_user, "NOTES_UPDATED")
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
    utc_timestamps: bool = False,
    include_unmapped_network: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    if not incident_id.startswith("INC-"):
        raise HTTPException(
            status_code=400,
            detail="Invalid incident ID.",
        )

    try:
        event_id = int(
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
            owned_security_event_filter(db, current_user),
            SecurityEvent.id == event_id,
            or_(
                SecurityEvent.mitre_technique_id.isnot(None),
                (
                    (SecurityEvent.source == "tshark-siem")
                    & (SecurityEvent.event_type == "network_detection")
                    if include_unmapped_network
                    else False
                ),
            ),
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
            detail="Incident not found.",
        )

    response = serialize_security_event_incident(event)

    persistent_case = (
        db.query(Incident)
        .filter(
            Incident.security_event_id == event.id
        )
        .first()
    )

    response["case"] = (
        serialize_case(persistent_case)
        if persistent_case
        else None
    )

    return _incident_utc_response(response) if utc_timestamps else response


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

