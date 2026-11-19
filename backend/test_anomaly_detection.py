import json
import uuid
from datetime import datetime, timedelta

from database import SessionLocal
from models import SecurityEvent, DetectionConfiguration, DetectionResult
from detection_engine import evaluate_event

db = SessionLocal()
suffix = uuid.uuid4().hex[:10]
rule = None
events = []

try:
    rule = DetectionConfiguration(
        name=f"TEST_ANOMALY_{suffix}",
        category="Test",
        description="Temporary anomaly detection test",
        detection_type="Anomaly-Based",
        severity="HIGH",
        conditions=json.dumps({
            "anomaly": {
                "baseline_window_minutes": 60,
                "detection_window_minutes": 5,
                "multiplier": 3,
                "minimum_events": 5,
                "group_by": "source",
            }
        }),
        enabled=True,
    )

    db.add(rule)
    db.flush()

    now = datetime.utcnow()

    # Historical baseline: 10 events in the preceding 55 minutes.
    for index in range(10):
        event = SecurityEvent(
            event_id=f"ANOMALY-TEST-{suffix}-BASE-{index}",
            timestamp=now - timedelta(minutes=55) + timedelta(minutes=index * 5),
            source="ANOMALY_TEST_SOURCE",
            event_type="LOGIN_FAILURE",
            severity="LOW",
            message="Temporary historical baseline event",
            target="test-system",
        )
        db.add(event)
        db.flush()
        events.append(event)

    # Recent burst: 5 events in the latest 5 minutes.
    for index in range(5):
        event = SecurityEvent(
            event_id=f"ANOMALY-TEST-{suffix}-RECENT-{index}",
            timestamp=now - timedelta(minutes=4) + timedelta(seconds=index * 30),
            source="ANOMALY_TEST_SOURCE",
            event_type="LOGIN_FAILURE",
            severity="HIGH",
            message="Temporary recent burst event",
            target="test-system",
        )
        db.add(event)
        db.flush()
        events.append(event)

    result = evaluate_event(db, events[-1])
    db.flush()

    result_count = (
        db.query(DetectionResult)
        .filter(DetectionResult.detection_config_id == rule.id)
        .count()
    )

    print("Evaluation:", result)
    print("Anomaly results saved:", result_count)

    assert result_count == 1, (
        f"Expected 1 anomaly result, got {result_count}"
    )

    print("PASS: Abnormal event burst detected.")

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
    print("Temporary anomaly test records cleaned up.")
