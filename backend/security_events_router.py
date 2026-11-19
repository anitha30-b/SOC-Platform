from collections import defaultdict
from datetime import datetime, timezone
import re
from zoneinfo import ZoneInfo
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from database import get_db
from models import Assessment, SecurityEvent, SIEMRuleConfig, User
from rbac import require_role
from siem_correlation_engine import SIEM_RULES, apply_rule_config, reset_rule_config
from mitre import get_attack_id, get_attack_patterns, get_tactics
from sigma_router import list_rule_records
from security_event_scope import owned_security_event_filter


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

    network_event = raw_event
    if event.event_type == "network_detection":
        network_event = raw_event.get("trigger_event") or raw_event

    dns_event = raw_event
    if event.event_type == "dns_detection":
        dns_event = raw_event.get("trigger_event") or raw_event

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
        "network": {
            "source_ip": network_event.get("source_ip"),
            "destination_ip": network_event.get("destination_ip"),
            "source_port": network_event.get("source_port"),
            "destination_port": network_event.get("destination_port"),
            "protocol": network_event.get("protocol"),
        } if event.event_type in {"network_connection_attempt", "network_detection"} else None,
        "dns": {
            "query_name": dns_event.get("dns_query_name"),
            "query_type": dns_event.get("dns_query_type"),
            "source_ip": dns_event.get("source_ip"),
            "destination_ip": dns_event.get("destination_ip"),
            "source_port": dns_event.get("source_port"),
            "destination_port": dns_event.get("destination_port"),
            "protocol": dns_event.get("protocol"),
        } if event.event_type in {"dns_query", "dns_detection"} else None,

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
        "raw_event": raw_event if event.source == "snort" else None,
        "correlation": raw_event.get("correlation") if event.source == "snort" else None,
    }


@router.get("")
def get_security_events(
    limit: int = Query(100, ge=1, le=500),
    severity: str | None = Query(None),
    source: str | None = Query(None),
    event_type: list[str] | None = Query(None),
    mitre_technique: str | None = Query(None),
    search: str | None = Query(None, max_length=200),
    event_id: str | None = Query(None, min_length=1, max_length=255),
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    query = db.query(SecurityEvent).filter(
        owned_security_event_filter(db, current_user)
    )

    if event_id is not None:
        query = query.filter(SecurityEvent.event_id == event_id)

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


@router.get("/anomaly/baseline")
def get_anomaly_baseline(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    """Compare the latest completed 15-minute bucket with seven days of history."""
    from datetime import timedelta
    from math import ceil
    from statistics import median

    bucket_seconds = 900
    history_bucket_count = 7 * 24 * 4

    # SecurityEvent timestamps are stored as naive UTC timestamps.
    now_utc = datetime.now(timezone.utc)
    boundary_epoch = int(now_utc.timestamp() // bucket_seconds) * bucket_seconds
    window_end = datetime.fromtimestamp(
        boundary_epoch, tz=timezone.utc
    ).replace(tzinfo=None)
    window_start = window_end - timedelta(seconds=bucket_seconds)
    baseline_start = window_start - timedelta(days=7)

    current_bucket = boundary_epoch // bucket_seconds - 1
    history_indexes = range(
        current_bucket - history_bucket_count,
        current_bucket,
    )

    # Aggregate in PostgreSQL instead of loading individual events into memory.
    bucket_expr = func.floor(
        func.extract("epoch", SecurityEvent.timestamp) / bucket_seconds
    )
    aggregated = (
        db.query(
            SecurityEvent.event_type,
            bucket_expr.label("bucket_index"),
            func.count(SecurityEvent.id).label("event_count"),
        )
        .filter(
            owned_security_event_filter(db, current_user),
            SecurityEvent.timestamp >= baseline_start,
            SecurityEvent.timestamp < window_end,
        )
        .group_by(SecurityEvent.event_type, bucket_expr)
        .all()
    )

    counts = {}
    event_types = set()

    for event_type, bucket_index, event_count in aggregated:
        kind = str(event_type or "unknown")
        event_types.add(kind)
        counts[(kind, int(bucket_index))] = int(event_count)

    results = []
    for kind in sorted(event_types):
        current_count = counts.get((kind, current_bucket), 0)

        # Include zero-event buckets so the baseline is not biased upward
        # by considering only periods in which an event occurred.
        historical_counts = [
            counts.get((kind, index), 0)
            for index in history_indexes
        ]

        baseline_median = float(median(historical_counts))
        deviations = [
            abs(value - baseline_median)
            for value in historical_counts
        ]
        mad = float(median(deviations))

        raw_threshold = (
            baseline_median + 3 * 1.4826 * mad
            if mad > 0
            else baseline_median * 1.5
        )
        threshold = max(5, ceil(raw_threshold))

        results.append({
            "event_type": kind,
            "current_count": current_count,
            "baseline_median": baseline_median,
            "baseline_mad": mad,
            "threshold": threshold,
            "historical_buckets": len(historical_counts),
            "flagged": current_count >= threshold and current_count > 1,
        })

    results.sort(
        key=lambda row: (not row["flagged"], -row["current_count"], row["event_type"])
    )

    return {
        "mode": "historical_volume_baseline",
        "window_minutes": 15,
        "baseline_days": 7,
        "baseline_bucket_count": history_bucket_count,
        "window_start": window_start.isoformat() + "Z",
        "window_end": window_end.isoformat() + "Z",
        "baseline_start": baseline_start.isoformat() + "Z",
        "baseline_end": window_start.isoformat() + "Z",
        "events_in_current_window": sum(row["current_count"] for row in results),
        "event_type_count": len(results),
        "flagged_count": sum(1 for row in results if row["flagged"]),
        "event_types": results,
        "interpretation": (
            "Volume outliers for analyst review, not confirmed malicious activity. "
            "Sparse history and changes in event collection can affect the baseline."
        ),
    }


@router.get("/coverage/mitre")
def get_mitre_coverage(
    db: Session = Depends(get_db),
    current_user=Depends(require_role(1)),
):
    """Compare explicit rule-to-technique mappings with tenant-scoped observations."""
    catalogue = {}

    for obj in get_attack_patterns():
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = get_attack_id(obj)
        if not technique_id:
            continue

        technique_id = technique_id.upper()
        catalogue[technique_id] = {
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "tactics": get_tactics(obj),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
        }

    # Treat only explicit attack.tXXXX tags on valid Sigma rules as mappings.
    # Do not infer a technique from a rule name or event type.
    mappings = defaultdict(list)
    sigma_records = list_rule_records()
    unmapped_sigma_rules = []

    tag_pattern = re.compile(r"attack\.(t[0-9]{4}(?:\.[0-9]{3})?)", re.I)

    for record in sigma_records:
        if record.get("validation_status") != "VALID":
            unmapped_sigma_rules.append({
                "rule_id": record["rule_id"],
                "title": record["title"],
                "reason": "Rule is invalid or has a duplicate ID.",
            })
            continue

        rule_mapped_ids = set()
        for tag in record.get("tags", []):
            match = tag_pattern.fullmatch(str(tag).strip())
            if not match:
                continue

            technique_id = match.group(1).upper()
            if technique_id not in catalogue:
                continue

            rule_mapped_ids.add(technique_id)

        if not rule_mapped_ids:
            unmapped_sigma_rules.append({
                "rule_id": record["rule_id"],
                "title": record["title"],
                "reason": "No explicit technique tag matched the active local catalogue.",
            })

        for technique_id in sorted(rule_mapped_ids):
            mappings[technique_id].append({
                "rule_type": "Sigma",
                "rule_id": record["rule_id"],
                "rule_name": record["title"],
                "integration_status": record.get("integration_status", "UNKNOWN"),
            })

    # The SIEM rule definitions have no explicit technique-ID field today.
    siem_unmapped_rules = [
        {
            "rule_id": rule.get("id"),
            "rule_name": rule.get("name"),
            "reason": "No explicit technique ID is configured on this SIEM rule.",
        }
        for rule in SIEM_RULES
        if not (rule.get("technique_id") or rule.get("mitre_technique_id"))
    ]

    # Count only explicitly owned assessment or registered telemetry events.
    observed_query = (
        db.query(
            SecurityEvent.mitre_technique_id,
            func.count(SecurityEvent.id).label("event_count"),
        )
        .filter(
            SecurityEvent.mitre_technique_id.isnot(None),
            owned_security_event_filter(db, current_user),
        )
    )

    scope_description = (
        "Persisted events authorized by the existing event ownership filter, "
        "including direct ownership, client scope, assessments, and registered "
        "telemetry sources."
    )

    observed_counts = {
        str(technique_id).upper(): int(event_count)
        for technique_id, event_count in observed_query.group_by(
            SecurityEvent.mitre_technique_id
        ).all()
    }

    configured_ids = set(mappings)
    catalogue_ids = set(catalogue)
    observed_ids = {
        technique_id
        for technique_id, event_count in observed_counts.items()
        if event_count > 0
    }
    observed_catalogue_ids = observed_ids & catalogue_ids

    rows = []
    for technique_id, item in catalogue.items():
        configured_by = mappings.get(technique_id, [])
        event_count = observed_counts.get(technique_id, 0)
        configured = bool(configured_by)
        observed = event_count > 0

        if configured and observed:
            status = "CONFIGURED_AND_OBSERVED"
        elif configured:
            status = "CONFIGURED_NOT_OBSERVED"
        elif observed:
            status = "OBSERVED_NOT_CONFIGURED"
        else:
            status = "NOT_CONFIGURED_OR_OBSERVED"

        rows.append({
            **item,
            "configured": configured,
            "configured_by": configured_by,
            "observed": observed,
            "observed_event_count": event_count,
            "coverage_status": status,
        })

    rows.sort(key=lambda item: (
        not item["configured"],
        not item["observed"],
        item["technique_id"],
    ))

    return {
        "framework": "MITRE ATT&CK Enterprise",
        "version": "19.2",
        "catalogue_active_only": True,
        "catalogue_technique_count": len(catalogue),
        "configured_technique_count": len(configured_ids),
        "catalogue_techniques_without_explicit_mapping": len(
            catalogue_ids - configured_ids
        ),
        "observed_catalogue_technique_count": len(observed_catalogue_ids),
        "observed_configured_technique_count": len(
            observed_catalogue_ids & configured_ids
        ),
        "observed_without_configured_mapping_count": len(
            observed_catalogue_ids - configured_ids
        ),
        "observed_techniques_outside_catalogue": sorted(
            observed_ids - catalogue_ids
        ),
        "configured_mapping_count": sum(len(value) for value in mappings.values()),
        "sigma_rule_count": len(sigma_records),
        "sigma_rules_without_explicit_mapping": unmapped_sigma_rules,
        "siem_rule_count": len(SIEM_RULES),
        "siem_rules_without_explicit_mapping": siem_unmapped_rules,
        "observed_event_count": sum(observed_counts.values()),
        "observation_scope": scope_description,
        "interpretation": (
            "The catalogue excludes revoked and deprecated techniques. "
            "Configured coverage counts only explicit active-catalogue technique tags "
            "on valid Sigma rules; this does not establish detection effectiveness. "
            "Unmapped techniques are not automatically deployment deficiencies. "
            "Observations use the existing event ownership filter across all dates. "
            "Historical observations outside the active catalogue remain included "
            "in observed_event_count and observed_techniques_outside_catalogue."
        ),
        "techniques": rows,
    }


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
        "sigma_detection",
    )

    query = db.query(SecurityEvent).filter(
        SecurityEvent.event_type.in_(detection_types),
        owned_security_event_filter(db, current_user),
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
            SecurityEvent.mitre_technique_id.isnot(None),
            owned_security_event_filter(db, current_user),
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
            owned_security_event_filter(db, current_user),
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
            SecurityEvent.mitre_technique_id.isnot(None),
            owned_security_event_filter(db, current_user),
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
            owned_security_event_filter(db, current_user),
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
            SecurityEvent.event_id == event_id,
            owned_security_event_filter(db, current_user),
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
        .filter(
            SecurityEvent.event_id == event_id,
            owned_security_event_filter(db, current_user),
        )
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
        .filter(
            SecurityEvent.event_id == event_id,
            owned_security_event_filter(db, current_user),
        )
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
            SecurityEvent.event_id == event_id,
            owned_security_event_filter(db, current_user),
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