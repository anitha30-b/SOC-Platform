from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from siem_response import block_ip


SIEM_RULES = [
    {
        "id": "AUTH-001",
        "name": "Repeated Authentication Failures",
        "event_types": {
            "authentication",
            "authentication_failure",
        },
        "threshold": 5,
        "window_seconds": 60,
        "group_by": "source_ip",
        "severity": "HIGH",
        "response": "block_ip",
    },
    {
        "id": "AUTH-002",
        "name": "Password Spraying",
        "event_types": {
            "authentication_failure",
        },
        "threshold": 3,
        "window_seconds": 60,
        "group_by": "source_ip",
        "unique_field": "username",
        "unique_threshold": 3,
        "severity": "HIGH",
        "response": "block_ip",
    },
    {
        "id": "AUTH-003",
        "name": "Credential Stuffing",
        "event_types": {
            "authentication_failure",
        },
        "threshold": 5,
        "window_seconds": 60,
        "group_by": "source_ip",
        "unique_field": "username",
        "unique_threshold": 5,
        "severity": "HIGH",
        "response": "block_ip",
    },
    {
        "id": "AUTH-004",
        "name": "Distributed Brute Force",
        "event_types": {
            "authentication_failure",
        },
        "threshold": 3,
        "window_seconds": 60,
        "group_by": "username",
        "unique_field": "source_ip",
        "unique_threshold": 3,
        "severity": "HIGH",
        "response": "block_ip",
    },
    {
        "id": "PRIV-001",
        "name": "Repeated Privileged Commands",
        "event_types": {
            "privileged_command",
        },
        "threshold": 3,
        "window_seconds": 60,
        "group_by": "username",
        "severity": "MEDIUM",
        "response": None,
    },
    {
        "id": "PRIV-002",
        "name": "Privileged Group Membership Change Attempt",
        "event_types": {"privileged_group_change_attempt"},
        "threshold": 1,
        "window_seconds": 60,
        "group_by": "global",
        "severity": "HIGH",
        "response": None,
    },
    {
        "id": "ACCOUNT-001",
        "name": "New Account Creation",
        "event_types": {
            "account_creation",
        },
        "threshold": 1,
        "window_seconds": 60,
        "group_by": "global",
        "severity": "HIGH",
        "response": None,
    },
    {
        "id": "ACCOUNT-002",
        "name": "Account Modification",
        "event_types": {
            "account_modification",
        },
        "threshold": 1,
        "window_seconds": 60,
        "group_by": "global",
        "severity": "HIGH",
        "response": None,
    },
    {
        "id": "NET-001",
        "name": "Port Scan Detected",
        "event_types": {"network_connection_attempt"},
        "threshold": 10,
        "window_seconds": 30,
        "group_by": "source_ip",
        "unique_field": "destination_port",
        "unique_threshold": 10,
        "severity": "HIGH",
        "response": None,
    },
    {
        "id": "NET-002",
        "name": "Host Scan Detected",
        "event_types": {"network_connection_attempt"},
        "threshold": 10,
        "window_seconds": 30,
        "group_by": "source_ip",
        "unique_field": "destination_ip",
        "unique_threshold": 10,
        "severity": "HIGH",
        "response": None,
    },    {
        "id": "DNS-001",
        "name": "DNS High Unique-Query Burst",
        "event_types": {"dns_query"},
        "threshold": 30,
        "window_seconds": 60,
        "group_by": "source_ip",
        "unique_field": "dns_query_name",
        "unique_threshold": 30,
        "severity": "MEDIUM",
        "response": None,
    },
]


RECENT_EVENTS: List[Dict[str, Any]] = []
RECENT_ALERTS: Dict[str, datetime] = {}
ALERT_COOLDOWN_SECONDS = 60

def apply_rule_config(rule_id: str, threshold: int, window_seconds: int) -> bool:
    """Apply a validated tuning override to the in-process rule definition."""
    rule = next((item for item in SIEM_RULES if item["id"] == rule_id), None)
    if rule is None:
        return False

    rule.setdefault("_default_threshold", rule["threshold"])
    rule.setdefault("_default_window_seconds", rule["window_seconds"])
    rule["threshold"] = int(threshold)
    rule["window_seconds"] = int(window_seconds)
    return True


def reset_rule_config(rule_id: str) -> bool:
    """Restore a rule's original in-code threshold and window."""
    rule = next((item for item in SIEM_RULES if item["id"] == rule_id), None)
    if rule is None:
        return False

    default_threshold = int(
        rule.get("_default_threshold", rule["threshold"])
    )
    default_window = int(
        rule.get("_default_window_seconds", rule["window_seconds"])
    )

    rule.setdefault("_default_threshold", default_threshold)
    rule.setdefault("_default_window_seconds", default_window)
    rule["threshold"] = default_threshold
    rule["window_seconds"] = default_window
    return True


def load_persistent_rule_configs() -> int:
    """Load saved overrides at startup; leave defaults intact when none exist."""
    from database import SessionLocal
    from models import SIEMRuleConfig

    db = SessionLocal()
    try:
        configs = db.query(SIEMRuleConfig).all()
        applied = 0
        for config in configs:
            if apply_rule_config(
                config.rule_id,
                config.threshold,
                config.window_seconds,
            ):
                applied += 1
        return applied
    finally:
        db.close()



def _parse_timestamp(event: Dict[str, Any]) -> datetime:
    value = event.get("timestamp")

    if not value:
        return datetime.utcnow()

    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return datetime.utcnow()

    if parsed.tzinfo is not None:
        # Normalize aware timestamps to UTC before dropping tzinfo,
        # so events from journal, TCP, and DNS share one time basis.
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

    return parsed


def _extract_source_ip(event: Dict[str, Any]) -> str | None:
    structured_ip = event.get("source_ip")
    if structured_ip:
        return str(structured_ip).strip() or None

    message = str(event.get("message", ""))

    marker = " from "
    position = message.lower().find(marker)

    if position == -1:
        return None

    value = message[position + len(marker):]
    source_ip = value.split(" ", 1)[0].strip()

    return source_ip or None


def _extract_username(event: Dict[str, Any]) -> str | None:
    message = str(event.get("message", "")).strip()
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

        value = message[position + len(marker):]
        username = value.split(" from ", 1)[0].strip()

        if username:
            return username

    # sudo journal format:
    # username : TTY=pts/6 ; PWD=/path ; USER=root ; COMMAND=/usr/bin/id
    if " : TTY=" in message:
        privileged_user = message.split(" : TTY=", 1)[0].strip()
        if privileged_user:
            return privileged_user

    return None


def _group_value(event: Dict[str, Any], group_by: str) -> str | None:
    if group_by == "global":
        return "global"

    if group_by == "source_ip":
        return _extract_source_ip(event)

    if group_by == "target":
        value = event.get("target")
        return str(value) if value else None

    if group_by == "username":
        return _extract_username(event)

    return None


def _is_expected_siem_firewall_inspection(event: Dict[str, Any]) -> bool:
    """Identify only the two known read-only SIEM firewall inspection commands."""
    import shlex

    message = str(event.get("message", ""))
    marker = "COMMAND="
    if marker not in message:
        return False

    command_text = message.rsplit(marker, 1)[1].strip()
    try:
        command_args = shlex.split(command_text)
    except ValueError:
        return False

    known_read_only_commands = {
        (
            "/usr/local/sbin/soc-siem-firewall",
            "-S",
            "SIEM-BLOCK",
        ),
        (
            "/usr/local/sbin/soc-siem-firewall",
            "-C",
            "INPUT",
            "-j",
            "SIEM-BLOCK",
        ),
    }
    return tuple(command_args) in known_read_only_commands


def _event_matches_rule(
    event: Dict[str, Any],
    rule: Dict[str, Any],
) -> bool:
    if event.get("event_type") not in rule["event_types"]:
        return False

    # Exclude only the known read-only firewall checks from PRIV-001.
    if (
        rule.get("id") == "PRIV-001"
        and _is_expected_siem_firewall_inspection(event)
    ):
        return False

    return True


def _cooldown_key(
    rule: Dict[str, Any],
    group_value: str | None,
) -> str:
    return f"{rule['id']}:{group_value or 'global'}"


def evaluate_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluate one real SIEM event against configured rules.
    Returns detection records only when a rule actually matches.
    """

    global RECENT_EVENTS

    event_time = _parse_timestamp(event)

    RECENT_EVENTS.append({
        **event,
        "_parsed_timestamp": event_time,
    })

    cutoff = event_time - timedelta(seconds=300)

    RECENT_EVENTS = [
        item
        for item in RECENT_EVENTS
        if item["_parsed_timestamp"] >= cutoff
    ]

    detections = []

    for rule in SIEM_RULES:
        if not _event_matches_rule(event, rule):
            continue

        matching_events = [
            item
            for item in RECENT_EVENTS
            if _event_matches_rule(item, rule)
            and item["_parsed_timestamp"] <= event_time
            and (
                event_time - item["_parsed_timestamp"]
                <= timedelta(seconds=rule["window_seconds"])
            )
        ]

        groups = defaultdict(list)

        for item in matching_events:
            group_value = _group_value(
                item,
                rule["group_by"],
            )

            if group_value:
                groups[group_value].append(item)

        for group_value, group_events in groups.items():
            if len(group_events) < rule["threshold"]:
                continue

            unique_values = set()

            unique_field = rule.get("unique_field")
            if unique_field == "username":
                for item in group_events:
                    username = _extract_username(item)
                    if username:
                        unique_values.add(username)

            elif unique_field == "source_ip":
                for item in group_events:
                    source_ip = _extract_source_ip(item)
                    if source_ip:
                        unique_values.add(source_ip)

            elif unique_field == "destination_port":
                for item in group_events:
                    port = item.get("destination_port")
                    if port not in (None, ""):
                        unique_values.add(str(port))

            elif unique_field == "destination_ip":
                for item in group_events:
                    destination_ip = item.get("destination_ip")
                    if destination_ip not in (None, ""):
                        unique_values.add(str(destination_ip))

            elif unique_field == "dns_query_name":
                for item in group_events:
                    query_name = item.get("dns_query_name")
                    if query_name not in (None, ""):
                        unique_values.add(str(query_name).lower().rstrip("."))

            if unique_field and len(unique_values) < rule.get("unique_threshold", 1):
                continue

            cooldown_key = _cooldown_key(
                rule,
                group_value,
            )

            previous_alert = RECENT_ALERTS.get(
                cooldown_key
            )

            if previous_alert:
                if (
                    event_time - previous_alert
                    <= timedelta(seconds=ALERT_COOLDOWN_SECONDS)
                ):
                    continue

            RECENT_ALERTS[cooldown_key] = event_time

            response_actions = []

            if rule.get("response") == "block_ip":
                if rule.get("group_by") == "username":
                    for source_ip in unique_values:
                        response_actions.append(
                            block_ip(source_ip)
                        )
                else:
                    response_actions.append(
                        block_ip(group_value)
                    )

            detections.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "threshold": rule["threshold"],
                "window_seconds": rule["window_seconds"],
                "group_by": rule["group_by"],
                "group_value": group_value,
                "event_count": len(group_events),
                "response_actions": response_actions,
                "evidence": [
                    {
                        key: value
                        for key, value in item.items()
                        if key != "_parsed_timestamp"
                    }
                    for item in group_events
                ],
            })

    return detections
