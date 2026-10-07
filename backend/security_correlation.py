from datetime import datetime, timedelta
from typing import Any, Dict, List


def correlate_authentication_events(
    events: List[Dict[str, Any]],
    window_seconds: int = 60,
) -> List[Dict[str, Any]]:
    if not events:
        return []

    normalized_events = []

    for event in events:
        timestamp = event.get("timestamp")

        if not timestamp:
            continue

        try:
            parsed_timestamp = datetime.fromisoformat(timestamp)
        except (TypeError, ValueError):
            continue

        normalized_events.append({
            **event,
            "_parsed_timestamp": parsed_timestamp,
        })

    normalized_events.sort(
        key=lambda item: item["_parsed_timestamp"]
    )

    correlations = []
    current_group = []
    group_start = None

    for event in normalized_events:
        event_time = event["_parsed_timestamp"]

        if not current_group:
            current_group = [event]
            group_start = event_time
            continue

        window_end = group_start + timedelta(
            seconds=window_seconds
        )

        if event_time <= window_end:
            current_group.append(event)
        else:
            correlations.append(
                _build_correlation(current_group)
            )

            current_group = [event]
            group_start = event_time

    if current_group:
        correlations.append(
            _build_correlation(current_group)
        )

    return correlations


def _build_correlation(
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:

    authentication_failures = [
        event
        for event in events
        if (
            "failed password"
            in str(event.get("message", "")).lower()
            or
            "authentication failure"
            in str(event.get("message", "")).lower()
        )
    ]

    correlated_events = []

    for event in events:
        correlated_events.append({
            key: value
            for key, value in event.items()
            if key != "_parsed_timestamp"
        })

    return {
        "start_time": events[0]["_parsed_timestamp"].isoformat(),
        "end_time": events[-1]["_parsed_timestamp"].isoformat(),
        "event_count": len(events),
        "authentication_failure_count": len(
            authentication_failures
        ),
        "events": correlated_events,
    }


def detect_failed_login_threshold(
    correlation: Dict[str, Any],
    threshold: int = 3,
) -> bool:
    failure_count = int(
        correlation.get(
            "authentication_failure_count",
            0,
        )
    )

    return failure_count >= threshold


def detect_brute_force(
    correlation: Dict[str, Any],
    threshold: int = 3,
) -> Dict[str, Any]:

    failure_count = int(
        correlation.get(
            "authentication_failure_count",
            0,
        )
    )

    detected = failure_count >= threshold

    return {
        "detected": detected,
        "detection_type": (
            "brute_force"
            if detected
            else None
        ),
        "failure_count": failure_count,
        "threshold": threshold,
        "start_time": correlation.get("start_time"),
        "end_time": correlation.get("end_time"),
        "evidence": correlation.get("events", []),
    }


def _extract_username(
    event: Dict[str, Any],
) -> str | None:

    message = str(
        event.get("message", "")
    ).strip()

    lower_message = message.lower()

    markers = [
        "failed password for invalid user ",
        "failed password for ",
        "invalid user ",
    ]

    for marker in markers:
        position = lower_message.find(marker)

        if position == -1:
            continue

        value = message[
            position + len(marker):
        ]

        username = value.split(
            " from ",
            1,
        )[0].strip()

        if username:
            return username

    return None


def detect_password_spraying(
    correlation: Dict[str, Any],
    minimum_users: int = 3,
    minimum_failures: int = 3,
) -> Dict[str, Any]:

    events = correlation.get(
        "events",
        [],
    )

    usernames = []

    for event in events:
        username = _extract_username(event)

        if username and username not in usernames:
            usernames.append(username)

    failure_count = int(
        correlation.get(
            "authentication_failure_count",
            0,
        )
    )

    detected = (
        failure_count >= minimum_failures
        and len(usernames) >= minimum_users
    )

    return {
        "detected": detected,
        "detection_type": (
            "password_spraying"
            if detected
            else None
        ),
        "failure_count": failure_count,
        "unique_user_count": len(usernames),
        "usernames": usernames,
        "minimum_failures": minimum_failures,
        "minimum_users": minimum_users,
        "start_time": correlation.get("start_time"),
        "end_time": correlation.get("end_time"),
        "evidence": events,
    }


def _extract_source_ip(
    event: Dict[str, Any],
) -> str | None:

    message = str(
        event.get("message", "")
    ).strip()

    marker = " from "

    lower_message = message.lower()
    position = lower_message.find(marker)

    if position == -1:
        return None

    value = message[
        position + len(marker):
    ]

    source_ip = value.split(
        " ",
        1,
    )[0].strip()

    if source_ip:
        return source_ip

    return None


def detect_credential_stuffing(
    correlation: Dict[str, Any],
    minimum_users: int = 3,
    minimum_failures: int = 3,
) -> Dict[str, Any]:
    """
    Detects a credential-stuffing-like pattern when
    multiple distinct usernames experience authentication
    failures from the same source within the correlation
    window.

    This is a behavioral detection signal, not proof that
    stolen credentials were used.
    """

    events = correlation.get(
        "events",
        [],
    )

    usernames = []
    source_ips = []

    for event in events:
        username = _extract_username(event)
        source_ip = _extract_source_ip(event)

        if username and username not in usernames:
            usernames.append(username)

        if source_ip and source_ip not in source_ips:
            source_ips.append(source_ip)

    failure_count = int(
        correlation.get(
            "authentication_failure_count",
            0,
        )
    )

    same_source = len(source_ips) == 1

    detected = (
        failure_count >= minimum_failures
        and len(usernames) >= minimum_users
        and same_source
    )

    return {
        "detected": detected,
        "detection_type": (
            "credential_stuffing"
            if detected
            else None
        ),
        "failure_count": failure_count,
        "unique_user_count": len(usernames),
        "usernames": usernames,
        "source_ips": source_ips,
        "same_source": same_source,
        "minimum_failures": minimum_failures,
        "minimum_users": minimum_users,
        "start_time": correlation.get("start_time"),
        "end_time": correlation.get("end_time"),
        "evidence": events,
    }