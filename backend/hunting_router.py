from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session
from database import get_db
from models import SecurityEvent
from rbac import require_role
from security_event_scope import owned_security_event_filter
from saved_searches_router import _owned_searches

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])


@router.get("/dashboard")
def hunting_dashboard(
    hours: int = Query(default=24, ge=1, le=8760),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    query = db.query(SecurityEvent).filter(
        owned_security_event_filter(db, current_user),
        SecurityEvent.timestamp >= start.replace(tzinfo=None),
        SecurityEvent.timestamp <= end.replace(tzinfo=None),
    )
    levels = query.with_entities(
        SecurityEvent.severity, func.count(SecurityEvent.id)
    ).group_by(SecurityEvent.severity).all()
    types = query.with_entities(
        SecurityEvent.event_type, func.count(SecurityEvent.id)
    ).group_by(SecurityEvent.event_type).order_by(
        func.count(SecurityEvent.id).desc(), SecurityEvent.event_type.asc()
    ).limit(10).all()
    recent = query.order_by(
        SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()
    ).limit(10).all()

    def utc(value):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    return {
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "scope": "client" if current_user.client_id is not None else "personal",
        "total_events": sum(count for _, count in levels),
        "high_severity_events": sum(
            count for level, count in levels
            if str(level).upper() in {"HIGH", "CRITICAL", "ERROR"}
        ),
        "mitre_mapped_events": query.filter(
            SecurityEvent.mitre_technique_id.isnot(None),
            SecurityEvent.mitre_technique_id != "",
        ).count(),
        "saved_queries": _owned_searches(db, current_user).count(),
        "top_event_types": [
            {"event_type": kind, "count": count} for kind, count in types
        ],
        "recent_events": [
            {
                "id": item.id, "timestamp": utc(item.timestamp),
                "severity": item.severity, "source": item.source,
                "event_type": item.event_type, "message": item.message,
            } for item in recent
        ],
    }


# Read-only hunting views. All database reads are ownership scoped.
@router.get("/explore/{kind}")
def hunting_explore(
    kind: str,
    hours: int = Query(default=24, ge=1, le=8760),
    search: str = Query(default="", max_length=200),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    import json
    from fastapi import HTTPException
    from models import EndpointAsset, EndpointProcess, User

    if kind not in {"users", "processes", "network", "timeline"}:
        raise HTTPException(status_code=404, detail="Unknown hunting view")

    def utc(value):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    needle = search.strip().casefold()

    def matches(row):
        return not needle or needle in json.dumps(
            row, ensure_ascii=False, default=str
        ).casefold()

    scope = "client" if current_user.client_id is not None else "personal"
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    scanned = 0
    rows = []

    if kind == "processes":
        owners = db.query(User.id)
        owners = owners.filter(
            User.client_id == current_user.client_id
        ) if current_user.client_id is not None else owners.filter(
            User.id == current_user.id
        )
        query = db.query(EndpointProcess, EndpointAsset).join(
            EndpointAsset,
            EndpointAsset.id == EndpointProcess.endpoint_asset_id,
        ).filter(EndpointAsset.user_id.in_(owners))
        candidates = query.order_by(
            EndpointProcess.last_seen.desc(), EndpointProcess.id.desc()
        ).limit(5001).all()
        has_more = len(candidates) > 5000
        candidates = candidates[:5000]
        scanned = len(candidates)
        for process, endpoint in candidates:
            row = {
                "id": process.id,
                "last_seen": utc(process.last_seen),
                "first_seen": utc(process.first_seen),
                "hostname": endpoint.hostname,
                "endpoint_id": endpoint.endpoint_id,
                "pid": process.pid,
                "parent_pid": process.parent_pid,
                "name": process.name,
                "executable": process.executable,
                "command_line": process.command_line,
                "username": process.username,
                "status": process.status,
            }
            if matches(row):
                rows.append(row)
        note = (
            "Collected process inventory, ordered by last observation. "
            "This is not process execution history or proof that a process "
            "is still running. The time-window selector does not apply."
        )
    else:
        query = db.query(SecurityEvent).filter(
            owned_security_event_filter(db, current_user),
            SecurityEvent.timestamp >= start.replace(tzinfo=None),
            SecurityEvent.timestamp <= end.replace(tzinfo=None),
        )
        if kind == "network":
            query = query.filter(SecurityEvent.event_type.in_({
                "network_connection_attempt", "network_detection",
                "dns_query", "dns_detection",
            }))
        candidates = query.order_by(
            SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()
        ).limit(5001).all()
        has_more = len(candidates) > 5000
        candidates = candidates[:5000]
        scanned = len(candidates)

        for event in candidates:
            try:
                raw = event.raw_event
                raw = json.loads(raw) if isinstance(raw, str) else raw
            except (ValueError, TypeError):
                raw = {}
            raw = raw if isinstance(raw, dict) else {}
            containers = [raw]
            for key in ("payload", "trigger_event"):
                value = raw.get(key)
                if isinstance(value, dict):
                    containers.append(value)
                    for nested in ("payload", "raw_event"):
                        item = value.get(nested)
                        if isinstance(item, dict):
                            containers.append(item)
                            if isinstance(item.get("payload"), dict):
                                containers.append(item["payload"])

            def field(*keys):
                for container in containers:
                    for key in keys:
                        value = container.get(key)
                        if isinstance(value, (str, int, float)) and str(value).strip():
                            return value
                return None

            username = field("username", "user_name", "user")
            row = {
                "id": event.id,
                "timestamp": utc(event.timestamp),
                "severity": event.severity,
                "source": event.source,
                "event_type": event.event_type,
                "target": event.target,
                "message": event.message,
            }
            if kind == "users":
                if username is not None:
                    identity = {
                        "username": username,
                        "identity_basis": "Recorded structured field",
                        "identity_role": "Not specified by this view",
                    }
                else:
                    from hunting_identity import extract_message_identity
                    identity = extract_message_identity(
                        event.event_type, event.message
                    )
                if identity is None:
                    continue
                row.update(identity)
            elif kind == "network":
                row.update({
                    "source_ip": field("source_ip"),
                    "destination_ip": field("destination_ip"),
                    "source_port": field("source_port"),
                    "destination_port": field("destination_port"),
                    "protocol": field("protocol"),
                    "dns_query": field("dns_query_name"),
                })
            if matches(row):
                rows.append(row)
        note = (
            "Recorded events within the selected UTC window. "
            "Newest events are examined first."
        )
        if kind == "users":
            note += (
                " Includes structured usernames and accounts parsed from "
                "recognized SSH or sudo/PAM messages. Open Details to see "
                "the identity basis and account role. Parsed text is not "
                "independent verification of identity."
            )

    matched = len(rows)
    return {
        "scope": scope,
        "window_start": None if kind == "processes" else start.isoformat(),
        "window_end": None if kind == "processes" else end.isoformat(),
        "scanned": scanned,
        "scan_limit": 5000,
        "scan_truncated": has_more,
        "matched_in_scanned": matched,
        "returned": min(matched, 500),
        "results_truncated": matched > 500,
        "note": note,
        "rows": rows[:500],
    }


@router.get("/identity-summary")
def identity_summary(
    hours: int = Query(default=0, ge=0, le=8760),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    """Full scoped identity-event counts; recent rows are separately limited."""
    auth_types = {
        "authentication", "authentication_success", "authentication_session",
        "authentication_failure", "invalid_user",
    }
    privileged_types = {
        "privileged_command", "privileged_session_opened",
        "privileged_session_closed", "privileged_group_change_attempt",
    }
    change_types = {
        "account_creation", "account_modification", "password_change",
    }
    eligible_types = auth_types | privileged_types | change_types
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours) if hours else None

    query = db.query(SecurityEvent).filter(
        owned_security_event_filter(db, current_user),
        SecurityEvent.event_type.in_(eligible_types),
        SecurityEvent.timestamp <= end.replace(tzinfo=None),
    )
    if start is not None:
        query = query.filter(
            SecurityEvent.timestamp >= start.replace(tzinfo=None)
        )

    counts = {
        kind: int(total)
        for kind, total in query.with_entities(
            SecurityEvent.event_type, func.count(SecurityEvent.id)
        ).group_by(SecurityEvent.event_type).all()
    }

    def total(kinds):
        return sum(counts.get(kind, 0) for kind in kinds)

    def utc(value):
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    recent = query.order_by(
        SecurityEvent.timestamp.desc(), SecurityEvent.id.desc()
    ).limit(10).all()

    return {
        "scope": "client" if current_user.client_id is not None else "personal",
        "window_start": start.isoformat() if start else None,
        "window_end": end.isoformat(),
        "all_dates": start is None,
        "total_events": sum(counts.values()),
        "authentication_records": total(auth_types),
        "failure_invalid_records": total({
            "authentication_failure", "invalid_user",
        }),
        "privileged_records": total(privileged_types),
        "account_change_records": total(change_types),
        "by_event_type": counts,
        "recent_limit": 10,
        "recent_events": [
            {
                "id": item.id,
                "timestamp": utc(item.timestamp),
                "event_type": item.event_type,
                "severity": item.severity,
                "source": item.source,
                "message": item.message,
            }
            for item in recent
        ],
    }
