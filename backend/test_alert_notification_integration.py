import uuid
from datetime import datetime

from database import SessionLocal
from models import SecurityEvent, AlertResult, Notification
from notification_service import create_alert_notifications_for_event

db = SessionLocal()
event_id = f"TEST-ALERT-{uuid.uuid4().hex[:12]}"

event = None
alert = None

try:
    event = SecurityEvent(
        event_id=event_id,
        timestamp=datetime.utcnow(),
        source="integration-test",
        event_type="TEST_BRUTE_FORCE",
        severity="HIGH",
        message="Controlled alert notification integration test",
        target="192.0.2.100",
        raw_event="{}",
        created_at=datetime.utcnow(),
        alert_status="Open",
    )

    db.add(event)
    db.flush()

    alert = AlertResult(
        security_event_id=event.id,
        alert_config_id=1,
        alert_name="Integration Test Alert",
        severity="HIGH",
        priority="P1",
        match_details="Controlled integration test",
        created_at=datetime.utcnow(),
    )

    db.add(alert)
    db.commit()

    print(f"Test event created: {event_id}")
    print(f"Test alert created: {alert.id}")

    payload = {"event_id": event_id}

    first_count = create_alert_notifications_for_event(payload)
    second_count = create_alert_notifications_for_event(payload)

    notification_event_id = f"ALERT-{alert.id}"

    notification_count = (
        db.query(Notification)
        .filter(Notification.event_id == notification_event_id)
        .count()
    )

    print(f"First processing count: {first_count}")
    print(f"Second processing count: {second_count}")
    print(f"Alert notifications in database: {notification_count}")

    assert notification_count == 1, (
        f"Expected exactly one notification, found {notification_count}"
    )

    notification = (
        db.query(Notification)
        .filter(Notification.event_id == notification_event_id)
        .first()
    )

    assert notification is not None
    assert notification.severity == "HIGH"
    assert "Priority: P1" in notification.message

    print("PASS: Alert notification created exactly once.")
    print("PASS: Severity and priority are included.")

finally:
    db.rollback()

    if event is not None and alert is not None:
        # Remove only records created by this test.
        db.query(Notification).filter(
            Notification.event_id == f"ALERT-{alert.id}"
        ).delete(synchronize_session=False)

        db.query(AlertResult).filter(
            AlertResult.id == alert.id
        ).delete(synchronize_session=False)

        db.query(SecurityEvent).filter(
            SecurityEvent.event_id == event_id
        ).delete(synchronize_session=False)

        db.commit()
        print("Test records cleaned up.")

    db.close()
