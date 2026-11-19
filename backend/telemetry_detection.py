"""Tenant-scoped Sigma and SIEM evaluation for accepted telemetry."""
import json

from database import SessionLocal
from mitre_mapper import map_security_event
from models import SecurityEvent
from security_event_store import store_security_event
from security_events import generate_event_id
from sigma_evaluator import evaluate_sigma_event
from siem_correlation_engine import evaluate_event
from client_realtime_events import notify_client_security_event
from realtime_journal_listener import notify_security_event


def _persist_detection(event):
    db = SessionLocal()
    try:
        existing = db.query(SecurityEvent.id).filter(
            SecurityEvent.event_id == event["event_id"]
        ).first()
        if existing:
            return False
        store_security_event(db, event, map_security_event(event))
        db.commit()

        try:
            notify_client_security_event(event)
        except Exception as exc:
            print(f"[SOC TELEMETRY DETECTION REALTIME ERROR] {exc}", flush=True)

        try:
            notify_security_event(event)
        except Exception as exc:
            print(f"[SOC TELEMETRY DETECTION SIEM NOTIFY ERROR] {exc}", flush=True)

        return True
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def process_ingested_telemetry(event):
    """Evaluate one committed event without automatic firewall actions."""
    scope = event.get("_tenant_scope_key")
    ownership = {
        "assessment_id": event.get("assessment_id"),
        "client_id": event.get("client_id"),
        "owner_user_id": event.get("owner_user_id"),
        "telemetry_source_id": event.get("telemetry_source_id"),
        "endpoint_asset_id": event.get("endpoint_asset_id"),
        "_tenant_scope_key": scope,
    }
    counts = {"sigma": 0, "siem": 0}

    try:
        # The local Sigma evaluator supports Linux journal source names.
        # Adapt only its in-memory input for recognized event types; the stored
        # telemetry keeps its real source and authenticated ownership fields.
        sigma_input = event
        normalized_type = str(event.get("event_type") or "").casefold()
        supported_linux_types = {
            "authentication",
            "authentication_failure",
            "invalid_user",
            "privileged_command",
        }
        if (
            str(event.get("source") or "").startswith("telemetry:")
            and normalized_type in supported_linux_types
        ):
            sigma_input = {**event, "source": "systemd-journald"}

        matches = evaluate_sigma_event(sigma_input)
    except Exception as exc:
        print(f"[SOC TELEMETRY SIGMA ERROR] {exc}", flush=True)
        matches = []

    severity_map = {
        "informational": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }

    for match in matches:
        rule = match["rule"]
        trigger_id = str(event.get("event_id") or "unknown")
        detection_id = generate_event_id(json.dumps({
            "type": "sigma",
            "scope": scope,
            "rule_id": rule["id"],
            "trigger_event_id": trigger_id,
        }, sort_keys=True, separators=(",", ":"), default=str))

        detection = {
            "event_id": detection_id,
            "timestamp": event.get("timestamp"),
            "source": "sigma-detection-engine",
            "event_type": "sigma_detection",
            "severity": severity_map.get(
                str(rule.get("level", "informational")).casefold(), "INFO"
            ),
            "message": f"Sigma rule matched: {rule.get('title', rule['id'])}",
            "target": event.get("target"),
            **ownership,
            "raw_event": {
                "rule": f"SIGMA-{rule['id']}",
                "rule_id": rule["id"],
                "rule_name": rule.get("title", rule["id"]),
                "sigma_rule_id": rule["id"],
                "sigma_filename": match.get("filename"),
                "integration_status": "LIVE_ENABLED",
                "trigger_event_id": trigger_id,
                "trigger_event": {
                    "event_id": trigger_id,
                    "source": event.get("source"),
                    "event_type": event.get("event_type"),
                    "message": str(event.get("message") or "")[:4000],
                },
                "matched_selectors": match.get("matched_selectors", []),
                "evidence": match.get("evidence", ""),
                "condition": (rule.get("detection") or {}).get("condition"),
                "logsource": rule.get("logsource", {}),
                "tags": rule.get("tags", []),
                "response_actions": [],
            },
        }
        try:
            counts["sigma"] += int(_persist_detection(detection))
        except Exception as exc:
            print(f"[SOC TELEMETRY SIGMA PERSIST ERROR] {exc}", flush=True)

    # The SIEM engine is tenant-partitioned below. Ingested logs never trigger
    # automatic firewall blocking; detections can instead be reviewed normally.
    try:
        detections = evaluate_event(event, allow_response_actions=False)
    except Exception as exc:
        print(f"[SOC TELEMETRY SIEM ERROR] {exc}", flush=True)
        detections = []

    for item in detections:
        evidence = [
            {k: v for k, v in row.items() if not str(k).startswith("_")}
            for row in item.get("evidence", [])
        ]
        detection_id = generate_event_id(json.dumps({
            "type": "siem",
            "scope": scope,
            "rule_id": item.get("rule_id"),
            "group_value": item.get("group_value"),
            "evidence_ids": [row.get("event_id") for row in evidence],
        }, sort_keys=True, separators=(",", ":"), default=str))

        detection = {
            "event_id": detection_id,
            "timestamp": event.get("timestamp"),
            "source": "siem-correlation-engine",
            "event_type": "siem_detection",
            "severity": item["severity"],
            "message": (
                f"{item['rule_name']} detected: {item['event_count']} matching "
                f"events from {item['group_value']}"
            ),
            "target": event.get("target"),
            **ownership,
            "raw_event": {
                "rule": item["rule_id"],
                "rule_name": item["rule_name"],
                "evidence": evidence,
                "threshold": item["threshold"],
                "window_seconds": item["window_seconds"],
                "event_count": item["event_count"],
                "group_by": item["group_by"],
                "group_value": item["group_value"],
                "response_actions": [],
            },
        }
        try:
            counts["siem"] += int(_persist_detection(detection))
        except Exception as exc:
            print(f"[SOC TELEMETRY SIEM PERSIST ERROR] {exc}", flush=True)

    return counts
