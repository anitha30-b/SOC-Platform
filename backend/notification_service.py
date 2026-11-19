import uuid
from datetime import datetime

from database import SessionLocal
from models import Assessment, Notification, NotificationChannelConfig, NotificationPolicy
from notification_broadcaster import notification_broadcaster
from user_notification_broadcaster import user_notification_broadcaster
from notification_security import decrypt_notification_secret


POLICY_SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

EVENT_SEVERITY_LEVEL = {
    "INFO": "INFO",
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
    "WARN": "MEDIUM",
    "WARNING": "MEDIUM",
    "ERROR": "HIGH",
}


def get_matching_policies(db, event):
    """Return enabled notification policies matching the security event."""
    source = str(event.get("source") or "").strip()
    event_type = str(event.get("event_type") or "").strip()
    severity = str(event.get("severity") or "INFO").upper().strip()

    normalized_severity = EVENT_SEVERITY_LEVEL.get(
        severity,
        "INFO",
    )

    event_level = POLICY_SEVERITY_ORDER.get(
        normalized_severity,
        POLICY_SEVERITY_ORDER["INFO"],
    )

    policies = (
        db.query(NotificationPolicy)
        .filter(NotificationPolicy.enabled.is_(True))
        .all()
    )

    matched = []

    for policy in policies:
        if policy.source:
            if policy.source.strip().lower() != source.lower():
                continue

        if policy.event_type:
            if policy.event_type.strip().lower() != event_type.lower():
                continue

        minimum = str(
            policy.minimum_severity or "INFO"
        ).upper().strip()

        minimum_level = POLICY_SEVERITY_ORDER.get(
            minimum,
            POLICY_SEVERITY_ORDER["INFO"],
        )

        if event_level < minimum_level:
            continue

        matched.append(policy)

    return matched


def send_email_notification(channel_config, notification):
    """Send one security notification through the configured SMTP server."""
    import json
    import smtplib
    from email.message import EmailMessage

    configuration = (
        json.loads(channel_config.configuration)
        if channel_config.configuration
        else {}
    )

    host = channel_config.endpoint
    username = channel_config.username
    from notification_security import decrypt_notification_secret
    password = decrypt_notification_secret(channel_config.secret)

    port = int(configuration.get("port", 587))
    from_address = configuration.get("from_address") or username
    recipients = configuration.get("to_addresses") or ""
    use_tls = configuration.get("use_tls", True)
    if isinstance(use_tls, str):
        use_tls = use_tls.strip().lower() in {"1", "true", "yes", "on"}

    if not host:
        raise ValueError("SMTP host is not configured.")

    if not from_address:
        raise ValueError("SMTP from_address is not configured.")

    if isinstance(recipients, str):
        recipients = [
            item.strip()
            for item in recipients.split(",")
            if item.strip()
        ]

    if not recipients:
        raise ValueError("SMTP recipient addresses are not configured.")

    message = EmailMessage()
    message["Subject"] = notification.title
    message["From"] = from_address
    message["To"] = ", ".join(recipients)
    message.set_content(
        f"{notification.message}\n\n"
        f"Severity: {notification.severity}\n"
        f"Source: {notification.source}\n"
        f"Event Type: {notification.event_type}\n"
        f"Target: {notification.target or 'N/A'}\n"
        f"Notification ID: {notification.notification_id}"
    )

    with smtplib.SMTP(host, port, timeout=15) as smtp:
        if use_tls:
            smtp.starttls()

        if username:
            smtp.login(username, password or "")

        smtp.send_message(message)


def send_slack_notification(channel_config, notification):
    """Send one security notification through a Slack Incoming Webhook."""
    import requests

    webhook_url = (
        decrypt_notification_secret(channel_config.secret)
        or channel_config.endpoint
    )

    if not webhook_url:
        raise ValueError("Slack webhook URL is not configured.")

    text = (
        f"*{notification.title}*\n"
        f"{notification.message}\n\n"
        f"*Severity:* {notification.severity}\n"
        f"*Source:* {notification.source}\n"
        f"*Event Type:* {notification.event_type}\n"
        f"*Target:* {notification.target or 'N/A'}\n"
        f"*Notification ID:* {notification.notification_id}"
    )

    response = requests.post(
        webhook_url,
        json={"text": text},
        timeout=15,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Slack webhook failed: HTTP {response.status_code} "
            f"- {response.text[:500]}"
        )

    if response.text.strip().lower() != "ok":
        raise RuntimeError(
            f"Slack webhook returned unexpected response: "
            f"{response.text[:500]}"
        )


def _notification_text(notification):
    return (
        f"{notification.title}\n"
        f"{notification.message}\n\n"
        f"Severity: {notification.severity}\n"
        f"Source: {notification.source}\n"
        f"Event Type: {notification.event_type}\n"
        f"Target: {notification.target or 'N/A'}\n"
        f"Notification ID: {notification.notification_id}"
    )


def send_teams_notification(channel_config, notification):
    import requests

    webhook_url = channel_config.endpoint
    if not webhook_url:
        raise ValueError("Microsoft Teams webhook URL is not configured.")

    response = requests.post(
        webhook_url,
        json={"text": _notification_text(notification)},
        timeout=15,
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"Teams webhook failed: HTTP {response.status_code} - "
            f"{response.text[:500]}"
        )


def send_webhook_notification(channel_config, notification):
    import json
    import requests

    endpoint = channel_config.endpoint
    if not endpoint:
        raise ValueError("Generic webhook URL is not configured.")

    configuration = (
        json.loads(channel_config.configuration)
        if channel_config.configuration
        else {}
    )

    method = str(configuration.get("method", "POST")).upper()
    content_type = str(
        configuration.get("content_type", "application/json")
    ).lower()

    payload = {
        "notification_id": notification.notification_id,
        "event_id": notification.event_id,
        "assessment_id": notification.assessment_id,
        "source": notification.source,
        "event_type": notification.event_type,
        "severity": notification.severity,
        "title": notification.title,
        "message": notification.message,
        "target": notification.target,
        "created_at": (
            notification.created_at.isoformat()
            if notification.created_at
            else None
        ),
    }

    headers = {"Content-Type": content_type}

    if channel_config.username:
        headers["X-Webhook-Username"] = channel_config.username

    if channel_config.secret:
        headers["Authorization"] = f"Bearer {channel_config.secret}"

    response = requests.request(
        method,
        endpoint,
        json=payload,
        headers=headers,
        timeout=15,
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"Generic webhook failed: HTTP {response.status_code} - "
            f"{response.text[:500]}"
        )



def create_alert_notification(event, alert_result):
    """
    Create a notification for a newly generated alert.

    Uses the existing notification policy matching and real-time
    notification broadcaster. External delivery is deliberately
    excluded from this first integration.
    """
    from models import AlertResult

    db = SessionLocal()

    try:
        # Confirm that this alert result is persisted.
        persisted_alert = (
            db.query(AlertResult)
            .filter(AlertResult.id == alert_result.id)
            .first()
        )

        if not persisted_alert:
            return None

        notification_event_id = (
            f"ALERT-{persisted_alert.id}"
        )

        existing = (
            db.query(Notification)
            .filter(
                Notification.event_id == notification_event_id
            )
            .first()
        )

        if existing:
            return existing

        severity = str(
            persisted_alert.severity or "INFO"
        ).upper()

        event_payload = {
            "event_id": notification_event_id,
            "assessment_id": event.assessment_id,
            "source": event.source,
            "event_type": f"ALERT:{event.event_type}",
            "severity": severity,
            "message": (
                f"Detection alert: {persisted_alert.alert_name}. "
                f"Priority: {persisted_alert.priority}. "
                f"Original event: {event.message}"
            ),
            "target": event.target,
        }

        matched_policies = get_matching_policies(
            db,
            event_payload,
        )

        notification = Notification(
            notification_id=(
                f"NTF-ALERT-{uuid.uuid4().hex[:12].upper()}"
            ),
            event_id=notification_event_id,
            assessment_id=event.assessment_id,
            user_id=None,
            source=event.source,
            event_type=event_payload["event_type"],
            severity=severity,
            title=f"{severity} Detection Alert: {persisted_alert.alert_name}",
            message=event_payload["message"],
            target=event.target,
            is_read=False,
            created_at=datetime.utcnow(),
        )

        db.add(notification)
        db.commit()
        db.refresh(notification)

        policy_channels = {
            "email": any(p.email_enabled for p in matched_policies),
            "slack": any(p.slack_enabled for p in matched_policies),
            "teams": any(p.teams_enabled for p in matched_policies),
            "webhook": any(p.webhook_enabled for p in matched_policies),
        }

        slack_delivery = {
            "attempted": False,
            "sent": False,
            "error": None,
        }

        if (
            severity in {"HIGH", "CRITICAL"}
            and policy_channels["slack"]
        ):
            slack_config = (
                db.query(NotificationChannelConfig)
                .filter(
                    NotificationChannelConfig.channel == "slack",
                    NotificationChannelConfig.enabled.is_(True),
                )
                .first()
            )

            if slack_config:
                slack_delivery["attempted"] = True
                try:
                    send_slack_notification(
                        slack_config,
                        notification,
                    )
                    slack_delivery["sent"] = True
                except Exception:
                    slack_delivery["error"] = (
                        "Slack delivery failed. Check the saved "
                        "webhook configuration."
                    )

        payload = {
            "type": "notification",
            "notification_id": notification.notification_id,
            "event_id": notification.event_id,
            "assessment_id": notification.assessment_id,
            "source": notification.source,
            "event_type": notification.event_type,
            "severity": notification.severity,
            "title": notification.title,
            "message": notification.message,
            "target": notification.target,
            "is_read": notification.is_read,
            "policy_matched": bool(matched_policies),
            "policy_channels": policy_channels,
            "slack_delivery": slack_delivery,
            "alert_result_id": persisted_alert.id,
            "created_at": (
                notification.created_at.isoformat()
                if notification.created_at
                else None
            ),
        }

        notification_broadcaster.publish(payload)

        return notification

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def create_alert_notifications_for_event(event_payload):
    """
    Create notifications for all persisted alerts belonging to an event.
    Called after PostgreSQL confirms the event transaction has committed.
    """
    from models import AlertResult, SecurityEvent

    event_id = event_payload.get("event_id")
    if not event_id:
        return 0

    db = SessionLocal()
    try:
        event = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.event_id == event_id)
            .first()
        )

        if event is None:
            return 0

        alert_results = (
            db.query(AlertResult)
            .filter(AlertResult.security_event_id == event.id)
            .all()
        )

        # Keep only IDs; each notification helper uses its own DB session.
        alert_result_ids = [result.id for result in alert_results]

    finally:
        db.close()

    created_count = 0

    for alert_result_id in alert_result_ids:
        lookup_db = SessionLocal()
        try:
            alert_result = (
                lookup_db.query(AlertResult)
                .filter(AlertResult.id == alert_result_id)
                .first()
            )
            if alert_result is None:
                continue

            # Load the event again in this session.
            event = (
                lookup_db.query(SecurityEvent)
                .filter(SecurityEvent.event_id == event_id)
                .first()
            )
            if event is None:
                continue

            create_alert_notification(event, alert_result)
            created_count += 1
        finally:
            lookup_db.close()

    return created_count


def create_notification(event):
    db = SessionLocal()

    try:
        event_id = event.get("event_id")

        # Prevent duplicate notifications for the same event.
        if event_id:
            existing = (
                db.query(Notification)
                .filter(Notification.event_id == event_id)
                .first()
            )

            if existing:
                return existing

        assessment_id = event.get("assessment_id")
        notification_user_id = None

        if assessment_id is not None:
            assessment = (
                db.query(Assessment)
                .filter(Assessment.id == assessment_id)
                .first()
            )
            if assessment:
                notification_user_id = assessment.user_id

        severity = str(
            event.get("severity") or "INFO"
        ).upper()

        event_type = str(
            event.get("event_type")
            or "security_event"
        )

        source = str(
            event.get("source")
            or "unknown"
        )

        message = str(
            event.get("message")
            or "Security event detected"
        )

        notification = Notification(
            notification_id=f"NTF-{uuid.uuid4().hex[:12].upper()}",
            event_id=event_id,
            user_id=notification_user_id,
            assessment_id=assessment_id,
            source=source,
            event_type=event_type,
            severity=severity,
            title=f"{severity} Security Event",
            message=message,
            target=event.get("target"),
            is_read=False,
            created_at=datetime.utcnow(),
        )

        db.add(notification)
        db.commit()
        db.refresh(notification)

        # Evaluate enabled notification policies for this event.
        matched_policies = get_matching_policies(db, event)

        policy_channels = {
            "email": any(policy.email_enabled for policy in matched_policies),
            "slack": any(policy.slack_enabled for policy in matched_policies),
            "teams": any(policy.teams_enabled for policy in matched_policies),
            "webhook": any(policy.webhook_enabled for policy in matched_policies),
        }

        # Deliver email only when a matching policy enables email
        # and the email channel is explicitly enabled.
        email_delivery = {
            "attempted": False,
            "sent": False,
            "error": None,
        }

        if policy_channels["email"]:
            email_config = (
                db.query(NotificationChannelConfig)
                .filter(
                    NotificationChannelConfig.channel == "email",
                    NotificationChannelConfig.enabled.is_(True),
                )
                .first()
            )

            if email_config:
                email_delivery["attempted"] = True
                try:
                    send_email_notification(
                        email_config,
                        notification,
                    )
                    email_delivery["sent"] = True
                except Exception as exc:
                    email_delivery["error"] = str(exc)

        # Deliver Slack only when a matching policy enables Slack
        # and the Slack channel is explicitly enabled.
        slack_delivery = {
            "attempted": False,
            "sent": False,
            "error": None,
        }

        if policy_channels["slack"]:
            slack_config = (
                db.query(NotificationChannelConfig)
                .filter(
                    NotificationChannelConfig.channel == "slack",
                    NotificationChannelConfig.enabled.is_(True),
                )
                .first()
            )

            if slack_config:
                slack_delivery["attempted"] = True
                try:
                    send_slack_notification(
                        slack_config,
                        notification,
                    )
                    slack_delivery["sent"] = True
                except Exception as exc:
                    slack_delivery["error"] = str(exc)

        webhook_delivery = {
            "attempted": False,
            "sent": False,
            "error": None,
        }

        if policy_channels["webhook"]:
            webhook_config = (
                db.query(NotificationChannelConfig)
                .filter(
                    NotificationChannelConfig.channel == "webhook",
                    NotificationChannelConfig.enabled.is_(True),
                )
                .first()
            )

            if webhook_config:
                webhook_delivery["attempted"] = True
                try:
                    send_webhook_notification(
                        webhook_config,
                        notification,
                    )
                    webhook_delivery["sent"] = True
                except Exception as exc:
                    webhook_delivery["error"] = str(exc)

        payload = {
            "type": "notification",
            "notification_id": notification.notification_id,
            "event_id": notification.event_id,
            "assessment_id": notification.assessment_id,
            "source": notification.source,
            "event_type": notification.event_type,
            "severity": notification.severity,
            "title": notification.title,
            "message": notification.message,
            "target": notification.target,
            "is_read": notification.is_read,
            "policy_matched": bool(matched_policies),
            "policy_channels": policy_channels,
            "email_delivery": email_delivery,
            "slack_delivery": slack_delivery,
            "webhook_delivery": webhook_delivery,
            "created_at": (
                notification.created_at.isoformat()
                if notification.created_at
                else None
            ),
        }

        # Reuse the existing real-time broadcaster.
        notification_broadcaster.publish(payload)

        # Publish only to the notification owner.
        if notification_user_id is not None:
            user_notification_broadcaster.publish(
                notification_user_id,
                payload,
            )

        return notification

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
