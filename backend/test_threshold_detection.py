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
rule = None
events = []

try:
    rule = DetectionConfiguration(
        name=f"TEST_THRESHOLD_{suffix}",
        category="Test",
        description="Temporary threshold detection test",
        detection_type="Threshold-Based",
        severity="HIGH",
        threshold=3,
        time_window_minutes=5,
        source="THRESHOLD_TEST",
        event_type="LOGIN_FAILURE",
        conditions=None,
        enabled=True,
    )

    db.add(rule)
    db.flush()

    for index in range(1, 4):
        event = SecurityEvent(
            event_id=f"THRESHOLD-TEST-{suffix}-{index}",
            timestamp=datetime.utcnow() + timedelta(seconds=index),
            source="THRESHOLD_TEST",
            event_type="LOGIN_FAILURE",
            severity="HIGH",
            message=f"Temporary threshold test event {index}",
            target="127.0.0.1",
        )

        db.add(event)
        db.flush()
        events.append(event)

        result = evaluate_event(db, event)
        db.flush()

        print(f"Event {index}: {result}")

    result_count = (
        db.query(DetectionResult)
        .filter(DetectionResult.detection_config_id == rule.id)
        .count()
    )

    print(f"\nDetection results saved: {result_count}")

    assert result_count == 1, (
        f"Expected 1 threshold detection result, got {result_count}"
    )

    print("PASS: Threshold detection triggered at 3 events.")

finally:
    if rule is not None and rule.id is not None:
        db.query(DetectionResult).filter(
            DetectionResult.detection_config_id == rule.id
        ).delete(synchronize_session=False)

    for event in events:
        if event.id is not None:
            db.query(DetectionResult).filter(
                DetectionResult.security_event_id == event.id
            ).delete(synchronize_session=False)

            db.query(SecurityEvent).filter(
                SecurityEvent.id == event.id
            ).delete(synchronize_session=False)

    if rule is not None and rule.id is not None:
        db.query(DetectionConfiguration).filter(
            DetectionConfiguration.id == rule.id
        ).delete(synchronize_session=False)

    db.commit()
    db.close()
    print("Temporary threshold test records cleaned up.")
