import json
import logging
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError

from models import (
    SecurityEvent,
    DetectionConfiguration,
    AlertConfiguration,
    DetectionResult,
    AlertResult,
)

logger = logging.getLogger("soc.detection_engine")

ALLOWED_FIELDS = {
    "source",
    "event_type",
    "severity",
    "message",
    "target",
    "assessment_id",
    "mitre_technique_id",
    "mitre_tactic",
}

ALLOWED_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "starts_with",
    "ends_with",
}


def event_value(event, field):
    if field not in ALLOWED_FIELDS:
        raise ValueError(f"Unsupported condition field: {field}")

    return getattr(event, field, None)


def evaluate_condition(event, condition):
    if not condition:
        return True

    try:
        parsed = json.loads(condition)
    except (TypeError, json.JSONDecodeError):
        # Legacy free-text conditions are not executable.
        return False

    if not isinstance(parsed, dict):
        return False

    # A single condition:
    # {"field":"severity","operator":"equals","value":"CRITICAL"}
    # Multiple conditions:
    # {"all":[{...},{...}]} or {"any":[{...},{...}]}

    if "all" in parsed:
        rules = parsed["all"]
        return (
            isinstance(rules, list)
            and bool(rules)
            and all(evaluate_condition(event, json.dumps(rule)) for rule in rules)
        )

    if "any" in parsed:
        rules = parsed["any"]
        return (
            isinstance(rules, list)
            and bool(rules)
            and any(evaluate_condition(event, json.dumps(rule)) for rule in rules)
        )

    field = parsed.get("field")
    operator = parsed.get("operator")
    expected = parsed.get("value")

    if field not in ALLOWED_FIELDS or operator not in ALLOWED_OPERATORS:
        return False

    actual = event_value(event, field)

    if actual is None:
        return False

    actual = str(actual).lower()
    expected = str(expected).lower()

    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "contains":
        return expected in actual
    if operator == "starts_with":
        return actual.startswith(expected)
    if operator == "ends_with":
        return actual.endswith(expected)

    return False


def correlation_reached(db, event, rule):
    """
    Detect an ordered pair of related events.

    conditions format:
    {
        "correlation": {
            "first": {
                "field": "event_type",
                "operator": "equals",
                "value": "LOGIN_FAILURE"
            },
            "then": {
                "field": "event_type",
                "operator": "equals",
                "value": "LOGIN_SUCCESS"
            },
            "time_window_minutes": 10,
            "group_by": "source"
        }
    }
    """
    try:
        config = json.loads(rule.conditions or "{}")
        correlation = config.get("correlation")

        if not isinstance(correlation, dict):
            return False

        first_condition = correlation.get("first")
        then_condition = correlation.get("then")
        window = correlation.get("time_window_minutes", 10)
        group_by = correlation.get("group_by", "source")

        if not isinstance(first_condition, dict):
            return False

        if not isinstance(then_condition, dict):
            return False

        if group_by not in {"source", "target"}:
            return False

        window = int(window)
        if window <= 0 or window > 1440:
            return False

        if not evaluate_condition(event, json.dumps(then_condition)):
            return False

        event_time = event.timestamp
        start_time = event_time - timedelta(minutes=window)

        query = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= start_time,
            SecurityEvent.timestamp <= event_time,
            SecurityEvent.id != event.id,
        )

        group_value = getattr(event, group_by, None)

        if not group_value:
            return False

        query = query.filter(
            getattr(SecurityEvent, group_by) == group_value
        )

        previous_events = query.order_by(
            SecurityEvent.timestamp.desc()
        ).all()

        return any(
            evaluate_condition(previous, json.dumps(first_condition))
            for previous in previous_events
        )

    except (ValueError, TypeError, json.JSONDecodeError):
        logger.exception("Invalid correlation configuration for rule %s", rule.id)
        return False


def anomaly_reached(db, event, rule):
    """
    Compare recent event volume against a historical baseline.
    """
    try:
        config = json.loads(rule.conditions or "{}")
        anomaly = config.get("anomaly")

        if not isinstance(anomaly, dict):
            return False

        baseline_minutes = int(anomaly.get("baseline_window_minutes", 60))
        detection_minutes = int(anomaly.get("detection_window_minutes", 5))
        multiplier = float(anomaly.get("multiplier", 3))
        minimum_events = int(anomaly.get("minimum_events", 5))
        group_by = anomaly.get("group_by", "source")

        if (
            baseline_minutes <= detection_minutes
            or baseline_minutes > 10080
            or detection_minutes <= 0
            or detection_minutes > 1440
            or multiplier <= 0
            or minimum_events <= 0
            or group_by not in {"source", "event_type"}
        ):
            return False

        group_value = getattr(event, group_by, None)
        if not group_value:
            return False

        event_time = event.timestamp
        recent_start = event_time - timedelta(minutes=detection_minutes)
        baseline_start = event_time - timedelta(minutes=baseline_minutes)

        group_column = getattr(SecurityEvent, group_by)

        base_query = db.query(SecurityEvent).filter(
            group_column == group_value,
            SecurityEvent.source == event.source,
            SecurityEvent.event_type == event.event_type,
        )

        recent_count = base_query.filter(
            SecurityEvent.timestamp >= recent_start,
            SecurityEvent.timestamp <= event_time,
        ).count()

        baseline_count = base_query.filter(
            SecurityEvent.timestamp >= baseline_start,
            SecurityEvent.timestamp < recent_start,
        ).count()

        equivalent_windows = (
            baseline_minutes - detection_minutes
        ) / detection_minutes

        average_per_window = baseline_count / equivalent_windows
        required_count = max(
            minimum_events,
            average_per_window * multiplier,
        )

        return recent_count >= required_count

    except (ValueError, TypeError, json.JSONDecodeError):
        logger.exception("Invalid anomaly configuration for rule %s", rule.id)
        return False


def matches_detection(event, rule):
    detection_type = (rule.detection_type or "").strip().lower()

    if detection_type not in {
        "rule-based",
        "threshold-based",
        "correlation",
        "anomaly-based",
    }:
        return False

    if detection_type in {"correlation", "anomaly-based"}:
        try:
            config = json.loads(rule.conditions or "{}")
            key = "correlation" if detection_type == "correlation" else "anomaly"
            return isinstance(config.get(key), dict)
        except (ValueError, TypeError):
            return False

    return evaluate_condition(event, rule.conditions)


def matches_alert(event, rule):
    if rule.source and rule.source.strip().lower() != str(event.source).lower():
        return False

    if rule.event_type and rule.event_type.strip().lower() != str(event.event_type).lower():
        return False

    return evaluate_condition(event, rule.conditions)


def threshold_reached(db, event, threshold, window_minutes):
    if not threshold or not window_minutes:
        return False

    if threshold < 1 or window_minutes < 1:
        return False

    start_time = event.timestamp - timedelta(minutes=window_minutes)

    query = db.query(SecurityEvent).filter(
        SecurityEvent.timestamp >= start_time,
        SecurityEvent.timestamp <= event.timestamp,
    )

    if event.source:
        query = query.filter(SecurityEvent.source == event.source)

    if event.event_type:
        query = query.filter(SecurityEvent.event_type == event.event_type)

    return query.count() >= threshold


def save_detection_result(db, event, rule, details):
    existing = (
        db.query(DetectionResult)
        .filter(
            DetectionResult.security_event_id == event.id,
            DetectionResult.detection_config_id == rule.id,
        )
        .first()
    )

    if existing:
        return False

    result = DetectionResult(
        security_event_id=event.id,
        detection_config_id=rule.id,
        rule_name=rule.name,
        detection_type=rule.detection_type,
        severity=rule.severity,
        match_details=json.dumps(details, default=str),
    )

    db.add(result)
    db.flush()
    return True


def save_alert_result(db, event, rule, details):
    existing = (
        db.query(AlertResult)
        .filter(
            AlertResult.security_event_id == event.id,
            AlertResult.alert_config_id == rule.id,
        )
        .first()
    )

    if existing:
        return False

    result = AlertResult(
        security_event_id=event.id,
        alert_config_id=rule.id,
        alert_name=rule.name,
        severity=rule.severity,
        priority=rule.priority,
        match_details=json.dumps(details, default=str),
    )

    db.add(result)
    db.flush()
    return True


def evaluate_event(db, event):
    """
    Evaluate enabled detection and alert configurations for one
    newly stored SecurityEvent.

    Returns counts of newly recorded matches.
    """

    summary = {
        "detections_matched": 0,
        "alerts_generated": 0,
    }

    if not event.id:
        return summary

    detection_rules = (
        db.query(DetectionConfiguration)
        .filter(DetectionConfiguration.enabled.is_(True))
        .all()
    )

    alert_rules = (
        db.query(AlertConfiguration)
        .filter(AlertConfiguration.enabled.is_(True))
        .all()
    )

    for rule in detection_rules:
        try:
            if not matches_detection(event, rule):
                continue

            if rule.detection_type.strip().lower() == "threshold-based":
                if rule.threshold is None or not rule.time_window_minutes:
                    logger.warning(
                        "Threshold rule %s requires threshold and time_window_minutes",
                        rule.id,
                    )
                    continue

                if rule.source and rule.source.strip().lower() != event.source.strip().lower():
                    continue

                if rule.event_type and rule.event_type.strip().lower() != event.event_type.strip().lower():
                    continue

                if not threshold_reached(
                    db,
                    event,
                    rule.threshold,
                    rule.time_window_minutes,
                ):
                    continue

            if rule.detection_type.strip().lower() == "correlation":
                if not correlation_reached(db, event, rule):
                    continue

            if rule.detection_type.strip().lower() == "anomaly-based":
                if not anomaly_reached(db, event, rule):
                    continue

            created = save_detection_result(
                db,
                event,
                rule,
                {
                    "rule": rule.name,
                    "event_id": event.event_id,
                    "matched": True,
                },
            )

            if created:
                summary["detections_matched"] += 1

        except Exception:
            logger.exception(
                "Detection rule %s failed for event %s",
                rule.id,
                event.id,
            )

    for rule in alert_rules:
        try:
            if not matches_alert(event, rule):
                continue

            if rule.threshold is not None:
                if not threshold_reached(
                    db,
                    event,
                    rule.threshold,
                    rule.time_window_minutes,
                ):
                    continue

            created = save_alert_result(
                db,
                event,
                rule,
                {
                    "rule": rule.name,
                    "event_id": event.event_id,
                    "threshold": rule.threshold,
                    "time_window_minutes": rule.time_window_minutes,
                    "matched": True,
                },
            )

            if created:
                summary["alerts_generated"] += 1

        except Exception:
            logger.exception(
                "Alert rule %s failed for event %s",
                rule.id,
                event.id,
            )

    return summary
