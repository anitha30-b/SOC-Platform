import json
import uuid
from datetime import datetime, timedelta

from database import SessionLocal
from models import (
    SecurityEvent,
    DetectionConfiguration,
    DetectionResult,
)
from detection_engine import evaluate_event

db = SessionLocal()
suffix = uuid.uuid4().hex[:10]
rules = []
events = []

try:
    rule = DetectionConfiguration(
        name=f"TEST_CORRELATION_{suffix}",
        category="Test",
        description="Failed login followed by successful login",
        detection_type="Correlation",
        severity="HIGH",
        conditions=json.dumps({
            "correlation": {
                "first": {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "LOGIN_FAILURE",
                },
                "then": {
                    "field": "event_type",
                    "operator": "equals",
                    "value": "LOGIN_SUCCESS",
                },
                "time_window_minutes": 10,
                "group_by": "source",
            }
        }),
        enabled=True,
    )

    db.add(rule)
    db.flush()
    rules.append(rule)

    now = datetime.utcnow()

    scenarios = [
        ("192.0.2.10", "LOGIN_FAILURE", now),
        ("192.0.2.10", "LOGIN_SUCCESS", now + timedelta(seconds=10)),
        ("192.0.2.20", "LOGIN_FAILURE", now + timedelta(seconds=20)),
        ("192.0.2.30", "LOGIN_SUCCESS", now + timedelta(seconds=30)),
    ]

    for index, (source, event_type, timestamp) in enumerate(scenarios, 1):
        event = SecurityEvent(
            event_id=f"CORRELATION-TEST-{suffix}-{index}",
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity="HIGH",
            message=f"Temporary correlation test: {event_type}",
            target="test-system",
        )

        db.add(event)
        db.flush()
        events.append(event)

        result = evaluate_event(db, event)
        db.flush()

        print(
            f"Event {index}: source={source}, "
            f"type={event_type}, result={result}"
        )

    result_count = (
        db.query(DetectionResult)
        .filter(DetectionResult.detection_config_id == rule.id)
        .count()
    )

    print(f"\nCorrelation detection results: {result_count}")

    assert result_count == 1, (
        f"Expected exactly 1 correlation result, got {result_count}"
    )

    print("PASS: Same-source sequence detected.")
    print("PASS: Different-source sequence did not trigger.")

finally:
    for event in events:
        if event.id is not None:
            db.query(DetectionResult).filter(
                DetectionResult.security_event_id == event.id
            ).delete(synchronize_session=False)

            db.query(SecurityEvent).filter(
                SecurityEvent.id == event.id
            ).delete(synchronize_session=False)

    for rule in rules:
        if rule.id is not None:
            db.query(DetectionResult).filter(
                DetectionResult.detection_config_id == rule.id
            ).delete(synchronize_session=False)

            db.query(DetectionConfiguration).filter(
                DetectionConfiguration.id == rule.id
            ).delete(synchronize_session=False)

    db.commit()
    db.close()
    print("Temporary correlation test records cleaned up.")
