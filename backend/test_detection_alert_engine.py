import json
import uuid
from datetime import datetime

from database import SessionLocal
from models import (
    SecurityEvent,
    DetectionConfiguration,
    AlertConfiguration,
    DetectionResult,
    AlertResult,
)
from detection_engine import evaluate_event

db = SessionLocal()
suffix = uuid.uuid4().hex[:10]
event = None
detection_rule = None
alert_rule = None

try:
    detection_rule = DetectionConfiguration(
        name=f"TEST_DETECTION_{suffix}",
        category="Test",
        description="Temporary detection engine test",
        detection_type="Rule-Based",
        severity="HIGH",
        conditions=json.dumps({
            "field": "severity",
            "operator": "equals",
            "value": "CRITICAL",
        }),
        enabled=True,
    )

    alert_rule = AlertConfiguration(
        name=f"TEST_ALERT_{suffix}",
        category="Test",
        description="Temporary alert engine test",
        severity="CRITICAL",
        priority="HIGH",
        source="ENGINE_TEST",
        event_type="TEST_EVENT",
        threshold=None,
        time_window_minutes=None,
        conditions=None,
        enabled=True,
    )

    db.add_all([detection_rule, alert_rule])
    db.flush()

    event = SecurityEvent(
        event_id=f"ENGINE-TEST-{suffix}",
        timestamp=datetime.utcnow(),
        source="ENGINE_TEST",
        event_type="TEST_EVENT",
        severity="CRITICAL",
        message="Temporary event for detection and alert engine testing",
        target="127.0.0.1",
    )

    db.add(event)
    db.flush()

    first = evaluate_event(db, event)
    db.flush()

    detection_count_first = (
        db.query(DetectionResult)
        .filter(DetectionResult.security_event_id == event.id)
        .count()
    )

    alert_count_first = (
        db.query(AlertResult)
        .filter(AlertResult.security_event_id == event.id)
        .count()
    )

    second = evaluate_event(db, event)
    db.flush()

    detection_count_second = (
        db.query(DetectionResult)
        .filter(DetectionResult.security_event_id == event.id)
        .count()
    )

    alert_count_second = (
        db.query(AlertResult)
        .filter(AlertResult.security_event_id == event.id)
        .count()
    )

    print("\n--- DETECTION AND ALERT ENGINE TEST ---")
    print("First evaluation:", first)
    print("Second evaluation:", second)
    print("Detection results after first:", detection_count_first)
    print("Alert results after first:", alert_count_first)
    print("Detection results after second:", detection_count_second)
    print("Alert results after second:", alert_count_second)

    assert first["detections_matched"] == 1
    assert first["alerts_generated"] == 1
    assert detection_count_first == 1
    assert alert_count_first == 1
    assert detection_count_second == 1
    assert alert_count_second == 1

    print("\nPASS: Detection and alert results were generated.")
    print("PASS: Re-evaluation did not create duplicates.")

finally:
    if event is not None and event.id is not None:
        db.query(DetectionResult).filter(
            DetectionResult.security_event_id == event.id
        ).delete(synchronize_session=False)

        db.query(AlertResult).filter(
            AlertResult.security_event_id == event.id
        ).delete(synchronize_session=False)

        db.query(SecurityEvent).filter(
            SecurityEvent.id == event.id
        ).delete(synchronize_session=False)

    if detection_rule is not None and detection_rule.id is not None:
        db.query(DetectionConfiguration).filter(
            DetectionConfiguration.id == detection_rule.id
        ).delete(synchronize_session=False)

    if alert_rule is not None and alert_rule.id is not None:
        db.query(AlertConfiguration).filter(
            AlertConfiguration.id == alert_rule.id
        ).delete(synchronize_session=False)

    db.commit()
    db.close()
    print("\nTemporary test records cleaned up.")
