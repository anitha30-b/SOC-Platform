from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from database import get_db
from models import SecurityEvent, SIEMRuleConfig
from rbac import require_role
from siem_correlation_engine import SIEM_RULES, apply_rule_config, reset_rule_config


router = APIRouter(
    prefix="/security-events",
    tags=["SOC Security Events"],
)

IST = ZoneInfo("Asia/Kolkata")


def format_ist_timestamp(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(IST).isoformat()


def serialize_event(event):
    response_actions = []
    raw_event = {}

    if event.raw_event:
        try:
            decoded = (
                event.raw_event
                if isinstance(event.raw_event, dict)
                else json.loads(event.raw_event)
            )
            if isinstance(decoded, dict):
                raw_event = decoded
                response_actions = decoded.get("response_actions", [])
        except (json.JSONDecodeError, TypeError):
            pass

    raw_evidence = raw_event.get("evidence")
    event_count = raw_event.get("event_count")
    if event_count is None and isinstance(raw_evidence, list):
        event_count = len(raw_evidence)

    if isinstance(raw_evidence, (dict, list)):
        raw_evidence = json.dumps(
            raw_evidence, ensure_ascii=False, indent=2, default=str
        )
    elif raw_evidence is not None:
        raw_evidence = str(raw_evidence)

    return {
        "id": event.id,
        "event_id": event.event_id,
        "timestamp": format_ist_timestamp(event.timestamp),
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
            "tactic": (
                event.mitre_tactic.replace("-", " ").title().replace(" And ", " and ")
                if event.mitre_tactic
                else None
            ),
            "mapping_source": event.mitre_mapping_source,
            "confidence": event.mitre_confidence,
            "evidence": event.mitre_evidence,
        },

        # Alert lifecycle
        "alert_status": event.alert_status,
        "acknowledged_at": format_ist_timestamp(event.acknowledged_at),
        "resolved_at": format_ist_timestamp(event.resolved_at),

        "created_at": format_ist_timestamp(event.created_at),
        "detection": {
            "rule_id": raw_event.get("rule_id") or raw_event.get("rule"),
            "rule_name": raw_event.get("rule_name"),
            "group_value": raw_event.get("group_value"),
            "group_by": raw_event.get("group_by"),
            "evidence": raw_evidence,
            "threshold": raw_event.get("threshold"),
            "window_seconds": raw_event.get("window_seconds"),
            "event_count": event_count,
        },
        "response_actions": response_actions,
    }


@router.get("")
def get_security_events(
    limit: int = Query(100, ge=1, le=500),
    severity: str | None = Query(None),
    source: str | None = Query(None),
    mitre_technique: str | None = Query(None),
    search: str | None = Query(None, max_length=200),
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


@router.get("/alerts")
def get_alerts(
    limit: int = Query(200, ge=1, le=500),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    """Return persisted SIEM detections, separate from ordinary telemetry."""
    detection_types = (
        "authentication_detection",
        "siem_detection",
        "network_detection",
        "dns_detection",
    )

    query = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_(detection_types)
    )

    if severity and severity.strip().upper() not in {"ALL", "ANY"}:
        query = query.filter(
            SecurityEvent.severity == severity.strip().upper()
        )

    if status and status.strip().upper() not in {"ALL", "ANY"}:
        query = query.filter(
            SecurityEvent.alert_status == status.strip().upper()
        )

    events = (
        query.order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
        .all()
    )

    return {
        "count": len(events),
        "alerts": [serialize_event(event) for event in events],
    }


@router.get("/rules")
def list_siem_rule_configs(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    """Read effective SIEM rule configuration for the user-side dashboard."""
    saved = {
        row.rule_id: row
        for row in db.query(SIEMRuleConfig).all()
    }

    rules = []
    for rule in SIEM_RULES:
        row = saved.get(rule["id"])
        rules.append({
            "rule_id": rule["id"],
            "name": rule["name"],
            "event_types": sorted(rule["event_types"]),
            "threshold": row.threshold if row else rule["threshold"],
            "window_seconds": row.window_seconds if row else rule["window_seconds"],
            "default_threshold": rule.get("_default_threshold", rule["threshold"]),
            "default_window_seconds": rule.get(
                "_default_window_seconds", rule["window_seconds"]
            ),
            "group_by": rule.get("group_by"),
            "unique_field": rule.get("unique_field"),
            "unique_threshold": rule.get("unique_threshold"),
            "severity": rule["severity"],
            "response": rule.get("response"),
            "is_configured": row is not None,
            "updated_at": format_ist_timestamp(row.updated_at) if row else None,
        })

    return {"count": len(rules), "rules": rules}


@router.put("/rules/{rule_id}")
def update_siem_rule_config(
    rule_id: str,
    threshold: int = Body(..., ge=1, le=10000),
    window_seconds: int = Body(..., ge=1, le=3600),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    """Persist validated threshold/window overrides; administrator only."""
    rule = next((item for item in SIEM_RULES if item["id"] == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail="Unknown SIEM rule.")

    minimum_threshold = rule.get("unique_threshold", 1)
    if threshold < minimum_threshold:
        raise HTTPException(
            status_code=422,
            detail=f"Threshold cannot be below this rule's unique-value threshold ({minimum_threshold}).",
        )

    row = (
        db.query(SIEMRuleConfig)
        .filter(SIEMRuleConfig.rule_id == rule_id)
        .first()
    )

    if row is None:
        row = SIEMRuleConfig(
            rule_id=rule_id,
            threshold=threshold,
            window_seconds=window_seconds,
            updated_by=current_user.id,
        )
        db.add(row)
    else:
        row.threshold = threshold
        row.window_seconds = window_seconds
        row.updated_by = current_user.id

    db.commit()
    db.refresh(row)

    if not apply_rule_config(rule_id, threshold, window_seconds):
        raise HTTPException(status_code=500, detail="Unable to apply SIEM rule configuration.")

    return {
        "message": "SIEM rule configuration saved.",
        "rule_id": rule_id,
        "threshold": row.threshold,
        "window_seconds": row.window_seconds,
        "updated_at": format_ist_timestamp(row.updated_at),
    }


@router.delete("/rules/{rule_id}")
def reset_siem_rule_config(
    rule_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(3)),
):
    """Remove a saved override and restore the original rule defaults."""
    rule = next((item for item in SIEM_RULES if item["id"] == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail="Unknown SIEM rule.")

    row = (
        db.query(SIEMRuleConfig)
        .filter(SIEMRuleConfig.rule_id == rule_id)
        .first()
    )
    if row is not None:
        db.delete(row)
        db.commit()

    if not reset_rule_config(rule_id):
        raise HTTPException(status_code=500, detail="Unable to restore SIEM rule defaults.")

    return {
        "message": "SIEM rule restored to defaults.",
        "rule_id": rule_id,
        "threshold": rule["threshold"],
        "window_seconds": rule["window_seconds"],
        "is_configured": False,
    }


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


@router.patch("/{event_id}/suppress")
def suppress_security_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.event_id == event_id)
        .first()
    )

    if not event:
        raise HTTPException(status_code=404, detail="Security event not found.")

    if event.alert_status != "ACTIVE":
        raise HTTPException(
            status_code=400,
            detail="Only ACTIVE alerts can be suppressed.",
        )

    event.alert_status = "SUPPRESSED"
    db.commit()
    db.refresh(event)

    return {
        "message": "Security alert suppressed.",
        "alert": serialize_event(event),
    }


@router.patch("/{event_id}/unsuppress")
def unsuppress_security_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.event_id == event_id)
        .first()
    )

    if not event:
        raise HTTPException(status_code=404, detail="Security event not found.")

    if event.alert_status != "SUPPRESSED":
        raise HTTPException(
            status_code=400,
            detail="Only SUPPRESSED alerts can be reactivated.",
        )

    event.alert_status = "ACTIVE"
    db.commit()
    db.refresh(event)

    return {
        "message": "Security alert reactivated.",
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