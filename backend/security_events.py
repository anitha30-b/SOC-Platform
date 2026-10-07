import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def generate_event_id(raw_line: str) -> str:
    """
    Generate a deterministic identifier for a journal event.

    The same original journal line produces the same ID,
    allowing the ingestion layer to detect duplicates.
    """

    return hashlib.sha256(
        raw_line.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def create_security_event(
    *,
    source: str,
    event_type: str,
    message: str,
    severity: str = "INFO",
    timestamp: Optional[str] = None,
    target: Optional[str] = None,
    assessment_id: Optional[int] = None,
    raw_event: Optional[Dict[str, Any]] = None,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Create a normalized security event.
    """

    raw_event = raw_event or {}

    return {
        "event_id": event_id,
        "timestamp": (
            timestamp
            or datetime.now(timezone.utc).isoformat()
        ),
        "source": source,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "target": target,
        "assessment_id": assessment_id,
        "raw_event": raw_event,
    }


def normalize_log_event(
    log: Dict[str, Any],
    *,
    source: Optional[str] = None,
    event_type: str = "security_event",
    target: Optional[str] = None,
    assessment_id: Optional[int] = None,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convert an existing SOC log record into the
    normalized security-event structure.
    """

    return create_security_event(
        source=source or log.get(
            "source",
            "unknown",
        ),
        event_type=event_type,
        message=str(
            log.get("message")
            or log.get("event")
            or ""
        ),
        severity=str(
            log.get("level", "INFO")
        ).upper(),
        timestamp=log.get("timestamp"),
        target=target,
        assessment_id=assessment_id,
        raw_event=log,
        event_id=event_id,
    )
