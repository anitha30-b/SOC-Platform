import json
from datetime import datetime, timezone

from models import SecurityEvent


def parse_event_timestamp(timestamp):
    if not timestamp:
        return datetime.now(timezone.utc).replace(tzinfo=None)

    parsed = datetime.fromisoformat(timestamp)

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

    return parsed


def store_security_event(
    db,
    event,
    mitre_mapping=None,
):
    mitre_mapping = mitre_mapping or {}

    event_id = event.get("event_id")

    if event_id:
        existing_event = (
            db.query(SecurityEvent)
            .filter(
                SecurityEvent.event_id == event_id
            )
            .first()
        )

        if existing_event:
            return existing_event

    tactics = mitre_mapping.get(
        "tactics",
        [],
    )

    # Preserve the complete original normalized event.
    raw_event = event.get(
        "raw_event"
    )

    if not raw_event:
        raw_event = event.copy()

    security_event = SecurityEvent(
        event_id=event_id,
        timestamp=parse_event_timestamp(
            event.get("timestamp")
        ),
        source=event.get(
            "source",
            "unknown",
        ),
        event_type=event.get(
            "event_type",
            "security_event",
        ),
        severity=event.get(
            "severity",
            "INFO",
        ),
        message=str(
            event.get(
                "message",
                "",
            )
        ),
        target=event.get("target"),
        client_id=event.get("client_id"),
        owner_user_id=event.get("owner_user_id"),
        telemetry_source_id=event.get("telemetry_source_id"),
        endpoint_asset_id=event.get("endpoint_asset_id"),
        assessment_id=event.get(
            "assessment_id"
        ),

        # MITRE relationship
        mitre_technique_id=mitre_mapping.get(
            "technique_id"
        ),
        mitre_technique_name=mitre_mapping.get(
            "technique_name"
        ),
        mitre_tactic=(
            tactics[0]
            if tactics
            else None
        ),
        mitre_mapping_source=mitre_mapping.get(
            "mapping_source"
        ),
        mitre_confidence=mitre_mapping.get(
            "confidence"
        ),
        mitre_evidence=mitre_mapping.get(
            "evidence"
        ),

        # Alert lifecycle
        alert_status="ACTIVE",
        acknowledged_at=None,
        resolved_at=None,

        # Preserve original event evidence.
        raw_event=json.dumps(
            raw_event,
            default=str,
        ),
    )

    db.add(security_event)
    db.flush()

    # Evaluate enabled detection and alert rules after the event
    # has received its database ID.
    try:
        from detection_engine import evaluate_event

        result = evaluate_event(db, security_event)

        print(
            "[SOC DETECTION ENGINE] "
            f"Event={security_event.event_id}; "
            f"Detections={result['detections_matched']}; "
            f"Alerts={result['alerts_generated']}",
            flush=True,
        )

    except Exception as exc:
        # Detection failures must not prevent normal event storage.
        print(
            "[SOC DETECTION ENGINE] Evaluation failed: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )

    return security_event