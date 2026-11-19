import os
import json
import re
import shlex
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone

import psycopg2
from siem_correlation_engine import evaluate_event

from database import DATABASE_URL, SessionLocal
from logs import format_journal_logs
from mitre_mapper import (
    map_detection_to_t1110,
    map_security_event,
)
from security_correlation import (
    correlate_authentication_events,
    detect_brute_force,
    detect_credential_stuffing,
    detect_password_spraying,
)
from security_event_store import store_security_event
from siem_response import block_ip
from security_events import (
    generate_event_id,
    normalize_log_event,
)
from models import SecurityEvent
from sigma_evaluator import evaluate_sigma_event
TSHARK_TELEMETRY_SOURCE_ID = os.getenv("TSHARK_TELEMETRY_SOURCE_ID")


def process_sigma_detections(event):
    """Evaluate and persist supported Sigma matches for one event."""
    try:
        matches = evaluate_sigma_event(event)
    except Exception as exc:
        print(f"[SOC SIGMA ERROR] Evaluation failed: {exc}", flush=True)
        return 0

    persisted = 0
    severity_map = {
        "informational": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }

    for match in matches:
        rule = match["rule"]
        trigger_id = str(
            event.get("event_id")
            or generate_event_id(json.dumps(event, sort_keys=True, default=str))
        )
        sigma_event_id = generate_event_id(json.dumps(
            {
                "sigma_rule_id": rule["id"],
                "trigger_event_id": trigger_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ))

        detection_event = {
            "event_id": sigma_event_id,
            "timestamp": event.get("timestamp"),
            "source": "sigma-detection-engine",
            "event_type": "sigma_detection",
            "severity": severity_map.get(
                str(rule.get("level", "informational")).casefold(), "INFO"
            ),
            "message": f"Sigma rule matched: {rule.get('title', rule['id'])}",
            "target": event.get("target"),
            "assessment_id": event.get("assessment_id"),
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

        db = SessionLocal()
        try:
            existing = (
                db.query(SecurityEvent)
                .filter(SecurityEvent.event_id == sigma_event_id)
                .first()
            )
            if existing:
                continue

            mapping = map_security_event(detection_event)
            store_security_event(db, detection_event, mapping)
            db.commit()
        except Exception as exc:
            db.rollback()
            print(
                f"[SOC SIGMA ERROR] {rule.get('title', rule['id'])}: {exc}",
                flush=True,
            )
            continue
        finally:
            db.close()

        try:
            notify_security_event(detection_event)
        except Exception as exc:
            print(f"[SOC SIGMA ERROR] Notification failed: {exc}", flush=True)

        persisted += 1
        print(
            f"[SOC SIGMA] {rule.get('title', rule['id'])} | "
            f"trigger={trigger_id}",
            flush=True,
        )

    return persisted


AUTHENTICATION_EVENT_WINDOW = timedelta(
    seconds=60
)

RECENT_AUTHENTICATION_EVENTS = []

RECENT_DETECTION_ALERTS = {}


def get_current_cursor():
    command = [
        "journalctl",
        "-u",
        "ssh.service",
        "-n",
        "1",
        "--show-cursor",
        "--no-pager",
        "-o",
        "short-iso",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=10,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or "Unable to read journal cursor"
        )

    for line in result.stdout.splitlines():
        line = line.strip()

        if line.startswith("-- cursor:"):
            return line.replace(
                "-- cursor:",
                "",
                1,
            ).strip()

    raise RuntimeError(
        "No journal cursor found"
    )


def notify_security_event(event):
    """
    Publish a persisted security event through
    PostgreSQL NOTIFY so other SOC processes can
    receive it in real time.

    PostgreSQL NOTIFY has a payload-size limit, so
    large raw evidence is not sent through the
    real-time channel. The complete event remains
    stored in PostgreSQL.
    """

    notification_event = dict(event)

    # The complete raw evidence is already persisted
    # in SecurityEvent.raw_event. Do not send large
    # evidence through PostgreSQL NOTIFY.
    notification_event.pop(
        "raw_event",
        None,
    )

    payload = json.dumps(
        notification_event,
        default=str,
    )

    connection = psycopg2.connect(
        DATABASE_URL
    )

    try:
        connection.autocommit = True

        cursor = connection.cursor()

        cursor.execute(
            "SELECT pg_notify(%s, %s)",
            (
                "security_events",
                payload,
            ),
        )

        cursor.close()

    finally:
        connection.close()


def add_authentication_event(event):
    """
    Keep recent authentication events in memory
    for real-time correlation.
    """

    global RECENT_AUTHENTICATION_EVENTS

    RECENT_AUTHENTICATION_EVENTS.append(
        event
    )

    current_timestamp = event.get(
        "timestamp"
    )

    if not current_timestamp:
        return

    try:
        current_time = datetime.fromisoformat(
            current_timestamp
        )
    except (TypeError, ValueError):
        return

    cutoff_time = (
        current_time
        - AUTHENTICATION_EVENT_WINDOW
    )

    filtered_events = []

    for existing_event in RECENT_AUTHENTICATION_EVENTS:
        timestamp = existing_event.get(
            "timestamp"
        )

        if not timestamp:
            continue

        try:
            event_time = datetime.fromisoformat(
                timestamp
            )
        except (TypeError, ValueError):
            continue

        if event_time >= cutoff_time:
            filtered_events.append(
                existing_event
            )

    RECENT_AUTHENTICATION_EVENTS = (
        filtered_events
    )


def should_emit_detection(
    detection,
    correlation,
):
    """
    Prevent duplicate detection alerts for the same
    behavioral pattern within the correlation window.

    Original authentication events are not affected.
    """

    detection_type = detection.get(
        "detection_type"
    )

    if not detection_type:
        return False

    usernames = tuple(
        sorted(
            detection.get(
                "usernames",
                [],
            )
        )
    )

    source_ips = tuple(
        sorted(
            detection.get(
                "source_ips",
                [],
            )
        )
    )

    # Deduplicate by the behavioral identity of the attack,
    # not by the rolling correlation window start time.
    #
    # The correlation window changes as new events arrive,
    # so including start_time can cause the same attack to
    # generate repeated detections.
    fingerprint = (
        detection_type,
        usernames,
        source_ips,
    )

    now = datetime.utcnow()

    previous_alert_time = (
        RECENT_DETECTION_ALERTS.get(
            fingerprint
        )
    )

    if previous_alert_time:
        if (
            now - previous_alert_time
            <= AUTHENTICATION_EVENT_WINDOW
        ):
            return False

    RECENT_DETECTION_ALERTS[
        fingerprint
    ] = now

    return True


def process_authentication_correlation(event):
    """
    Correlate recent authentication events and
    create MITRE-mapped detection events when
    a configured behavioral threshold is reached.
    """

    message = str(
        event.get("message", "")
    ).lower()

    if (
        "failed password" not in message
        and "authentication failure" not in message
    ):
        return []

    add_authentication_event(event)

    correlations = correlate_authentication_events(
        RECENT_AUTHENTICATION_EVENTS,
        window_seconds=60,
    )

    if not correlations:
        return []

    correlation = correlations[-1]

    detections = [
        detect_brute_force(
            correlation,
            threshold=3,
        ),
        detect_password_spraying(
            correlation,
            minimum_users=3,
            minimum_failures=3,
        ),
        detect_credential_stuffing(
            correlation,
            minimum_users=3,
            minimum_failures=3,
        ),
    ]

    detection_events = []

    for detection in detections:
        if not detection.get("detected"):
            continue

        if not should_emit_detection(
            detection,
            correlation,
        ):
            continue

        mapping = map_detection_to_t1110(
            detection,
            event,
        )

        if not mapping:
            continue

        response_actions = []

        for source_ip in detection.get("source_ips", []):
            response_actions.append(
                block_ip(source_ip)
            )

        detection_event = {
            "event_id": generate_event_id(
                json.dumps(
                    {
                        "detection": detection,
                        "event": event,
                    },
                    sort_keys=True,
                    default=str,
                )
            ),
            "timestamp": event.get(
                "timestamp"
            ),
            "source": "systemd-journald",
            "event_type": "authentication_detection",
            "severity": "ERROR",
            "message": (
                f"{detection.get('detection_type')} "
                "detected from correlated "
                "authentication events"
            ),
            "target": event.get(
                "target"
            ),
            "assessment_id": event.get(
                "assessment_id"
            ),
            "raw_event": {
                "trigger_event": event,
                "correlation": correlation,
                "detection": detection,
                "response_actions": response_actions,
            },
        }

        detection_events.append(
            (
                detection_event,
                mapping,
            )
        )

    return detection_events



def classify_journal_security_event(message):
    """
    Classify real system journal messages relevant to
    SIEM authentication and security monitoring.
    """

    raw_text = str(message)
    text = raw_text.lower()

    privileged_groups = {
        "sudo", "wheel", "admin", "admins",
        "docker", "lxd", "disk", "shadow",
    }

    command_match = re.search(r"\bCOMMAND=(.*)$", raw_text, re.IGNORECASE)
    command_text = command_match.group(1).strip() if command_match else raw_text

    try:
        tokens = shlex.split(command_text)
    except ValueError:
        tokens = command_text.split()

    command_names = {
        token.rsplit("/", 1)[-1].lower()
        for token in tokens
    }
    account_tools = {"usermod", "gpasswd", "adduser"}

    # Help/version invocations do not change group membership.
    if (
        command_names & account_tools
        and any(token.lower() in {"--help", "--version"} for token in tokens)
    ):
        return None

    def basename(token):
        return token.rsplit("/", 1)[-1].lower()

    executables = [basename(token) for token in tokens]

    def privileged_group_list(value):
        return bool({
            part.strip().strip("'\"").lower()
            for part in value.split(",")
        } & privileged_groups)

    # usermod -aG sudo user, usermod -G docker user, etc.
    has_privileged_usermod = False
    for i, token in enumerate(tokens):
        option = token.lower()
        group_value = None

        if option in ("-g", "-ag", "-a-g", "--groups"):
            if i + 1 < len(tokens):
                group_value = tokens[i + 1]
        elif option.startswith("--groups="):
            group_value = token.split("=", 1)[1]
        elif option.startswith("-ag") and len(token) > 3:
            group_value = token[3:]
        elif option.startswith("-g") and len(token) > 2:
            group_value = token[2:]

        if (
            group_value
            and "usermod" in executables
            and privileged_group_list(group_value)
        ):
            has_privileged_usermod = True
            break

    # gpasswd -a user group / gpasswd -d user group
    has_privileged_gpasswd = (
        "gpasswd" in executables
        and any(token.lower() in ("-a", "-d", "--add", "--delete")
                for token in tokens)
        and bool(tokens)
        and privileged_group_list(tokens[-1])
    )

    # adduser user group (membership assignment)
    has_privileged_adduser = (
        "adduser" in executables
        and len(tokens) >= 2
        and privileged_group_list(tokens[-1])
    )

    # Some Linux journal entries describe the resulting group change.
    audit_group_match = re.search(
        r"\bto group ['\"]?([a-z0-9_.-]+)",
        text,
    )
    has_privileged_audit_change = (
        "usermod[" in text
        and audit_group_match is not None
        and audit_group_match.group(1).lower() in privileged_groups
    )

    if (
        has_privileged_usermod
        or has_privileged_gpasswd
        or has_privileged_adduser
        or has_privileged_audit_change
    ):
        return "privileged_group_change_attempt"

    if "useradd" in text:
        return "account_creation"

    if "usermod" in text:
        return "account_modification"

    if "passwd" in text:
        return "password_change"

    if "sudo[" in text and "command=" in text:
        return "privileged_command"

    if "pam_unix(sudo:session)" in text and "session opened" in text:
        return "privileged_session_opened"

    if "pam_unix(sudo:session)" in text and "session closed" in text:
        return "privileged_session_closed"

    if "authentication failure" in text:
        return "authentication_failure"

    if "failed password" in text:
        return "authentication_failure"

    if "invalid user" in text:
        return "invalid_user"

    return None



def process_linux_security_event(raw_line):
    """
    Process a real system journal security event.

    Only messages classified by classify_journal_security_event()
    are ingested through this path.
    """

    classification = classify_journal_security_event(raw_line)

    if classification is None:
        return None

    logs = format_journal_logs(
        [raw_line],
        "system",
    )

    if not logs:
        return None

    log = logs[0]

    event = normalize_log_event(
        log,
        source="systemd-journald",
        event_type=classification,
        event_id=generate_event_id(raw_line),
    )

    db = SessionLocal()

    try:
        store_security_event(
            db,
            event,
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

    notify_security_event(event)
    process_sigma_detections(event)

    generic_detections = evaluate_event(event)

    for detection in generic_detections:
        detection_event = {
            "event_id": generate_event_id(
                json.dumps(
                    {
                        "rule_id": detection["rule_id"],
                        "group_value": detection["group_value"],
                        "evidence": detection["evidence"],
                    },
                    sort_keys=True,
                    default=str,
                )
            ),
            "timestamp": event.get("timestamp"),
            "source": "siem-correlation-engine",
            "event_type": "siem_detection",
            "severity": detection["severity"],
            "message": (
                f"{detection['rule_name']} detected: "
                f"{detection['event_count']} matching events "
                f"from {detection['group_value']}"
            ),
            "target": event.get("target"),
            "assessment_id": event.get("assessment_id"),
            "raw_event": {
                "rule": detection["rule_id"],
                "rule_name": detection["rule_name"],
                "trigger_event": event,
                "evidence": detection["evidence"],
                "threshold": detection["threshold"],
                "window_seconds": detection["window_seconds"],
                "event_count": detection["event_count"],
                "group_by": detection["group_by"],
                "group_value": detection["group_value"],
                "response_actions": detection["response_actions"],
            },
        }

        detection_mapping = map_security_event(
            detection_event
        )

        detection_db = SessionLocal()

        try:
            store_security_event(
                detection_db,
                detection_event,
                detection_mapping,
            )

            detection_db.commit()

        except Exception:
            detection_db.rollback()
            raise

        finally:
            detection_db.close()

        notify_security_event(detection_event)

        print(
            "[SOC GENERIC DETECTION] "
            f"{detection['rule_id']} | "
            f"{detection['rule_name']} | "
            f"{detection['group_value']} | "
            f"{detection['event_count']} events",
            flush=True,
        )

    print(
        "[SOC SIEM] "
        f"{classification} | "
        f"{event['message']}",
        flush=True,
    )

    return event



def run_linux_security_listener():
    """
    Read the real system journal continuously and process
    classified Linux security events.
    """

    command = [
        "stdbuf",
        "-oL",
        "journalctl",
        "-f",
        "-n",
        "0",
        "--no-pager",
        "-o",
        "short-iso",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        print(
            "[SOC LINUX LISTENER] Waiting for Linux security events...",
            flush=True,
        )

        while True:
            raw_line = process.stdout.readline()

            if not raw_line:
                if process.poll() is not None:
                    break
                continue

            raw_line = raw_line.strip()

            if not raw_line:
                continue

            process_linux_security_event(raw_line)

    except Exception as exc:
        print(
            f"[SOC LINUX LISTENER] Error: {exc}",
            flush=True,
        )

    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def run_listener():
    command = [
        "stdbuf",
        "-oL",
        "journalctl",
        "-u",
        "ssh.service",
        "-f",
        "--no-pager",
        "-o",
        "short-iso",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    try:
        print(
            "[SOC LISTENER] Waiting for new SSH events...",
            flush=True,
        )

        while True:
            raw_line = process.stdout.readline()

            if not raw_line:
                if process.poll() is not None:
                    break
                continue

            raw_line = raw_line.strip()

            if not raw_line:
                continue

            logs = format_journal_logs(
                [raw_line],
                "auth",
            )

            if not logs:
                continue

            log = logs[0]

            event = normalize_log_event(
                log,
                source="systemd-journald",
                event_type="authentication",
                event_id=generate_event_id(
                    raw_line
                ),
            )

            mappings = map_security_event(
                event
            )

            db = SessionLocal()

            try:
                if mappings:
                    for mapping in mappings:
                        store_security_event(
                            db,
                            event,
                            mapping,
                        )
                else:
                    store_security_event(
                        db,
                        event,
                    )

                db.commit()

            except Exception:
                db.rollback()
                raise

            finally:
                db.close()

            # Publish the original authentication
            # event only after successful database commit.
            notify_security_event(event)
            process_sigma_detections(event)

            detection_events = (
                process_authentication_correlation(
                    event
                )
            )

            for (
                detection_event,
                detection_mapping,
            ) in detection_events:

                detection_db = SessionLocal()

                try:
                    store_security_event(
                        detection_db,
                        detection_event,
                        detection_mapping,
                    )

                    detection_db.commit()

                except Exception:
                    detection_db.rollback()
                    raise

                finally:
                    detection_db.close()

                # Publish the detection only after
                # successful database commit.
                notify_security_event(
                    detection_event
                )

                print(
                    "[SOC DETECTION] "
                    f"{detection_mapping.get('technique_id')} | "
                    f"{detection_mapping.get('technique_name')}",
                    flush=True,
                )

            generic_detections = evaluate_event(event)

            for detection in generic_detections:
                detection_event = {
                    "event_id": generate_event_id(
                        json.dumps(
                            {
                                "rule_id": detection["rule_id"],
                                "group_value": detection["group_value"],
                                "evidence": detection["evidence"],
                            },
                            sort_keys=True,
                            default=str,
                        )
                    ),
                    "timestamp": event.get("timestamp"),
                    "source": "siem-correlation-engine",
                    "event_type": "siem_detection",
                    "severity": detection["severity"],
                    "message": (
                        f"{detection['rule_name']} detected: "
                        f"{detection['event_count']} matching events "
                        f"from {detection['group_value']}"
                    ),
                    "target": event.get("target"),
                    "assessment_id": event.get("assessment_id"),
                    "raw_event": {
                        "rule": detection["rule_id"],
                        "rule_name": detection["rule_name"],
                        "trigger_event": event,
                        "evidence": detection["evidence"],
                        "threshold": detection["threshold"],
                        "window_seconds": detection["window_seconds"],
                        "event_count": detection["event_count"],
                        "group_by": detection["group_by"],
                        "group_value": detection["group_value"],
                        "response_actions": detection["response_actions"],
                    },
                }

                detection_mapping = map_security_event(detection_event)
                detection_db = SessionLocal()

                try:
                    store_security_event(
                        detection_db,
                        detection_event,
                        detection_mapping,
                    )
                    detection_db.commit()
                except Exception:
                    detection_db.rollback()
                    raise
                finally:
                    detection_db.close()

                notify_security_event(detection_event)

                print(
                    "[SOC GENERIC DETECTION] "
                    f"{detection['rule_id']} | "
                    f"{detection['rule_name']} | "
                    f"{detection['group_value']} | "
                    f"{detection['event_count']} events",
                    flush=True,
                )

            print(
                f"[SOC EVENT] "
                f"{event['severity']} | "
                f"{event['message']}",
                flush=True,
            )

    except KeyboardInterrupt:
        print(
            "\n[SOC LISTENER] Stopped."
        )

    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)



_listener_thread = None
_linux_listener_thread = None
_tshark_listener_thread = None
_dns_listener_thread = None
_listener_lock = threading.Lock()



def _attach_registered_tshark_scope(event):
    """Resolve ownership from the registered local collector, not event input."""
    from models import TelemetrySource

    try:
        source_id = int(TSHARK_TELEMETRY_SOURCE_ID)
        if source_id <= 0:
            return False
    except (TypeError, ValueError):
        return False

    db = SessionLocal()
    try:
        registered = (
            db.query(TelemetrySource)
            .filter(
                TelemetrySource.id == source_id,
                TelemetrySource.enabled.is_(True),
            )
            .first()
        )
        if registered is None:
            return False

        if registered.client_id is not None:
            scope = f"client:{registered.client_id}"
        elif registered.owner_user_id is not None:
            scope = f"user:{registered.owner_user_id}"
        else:
            return False

        event.update({
            "telemetry_source_id": registered.id,
            "client_id": registered.client_id,
            "owner_user_id": registered.owner_user_id,
            "_tenant_scope_key": scope,
        })
        return True
    finally:
        db.close()


def run_tshark_security_listener():
    """Capture real TCP connection attempts and feed them into the SIEM engine."""
    command = [
        "sudo", "-n", "/usr/bin/tshark",
        "-i", "any",
        "-l",
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info",
        "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
    ]

    print("[SOC TSHARK] Starting real-time network listener...", flush=True)

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    for raw_line in process.stdout:
        line = raw_line.strip()
        if not line or line.startswith("Capturing"):
            continue

        fields = line.split("\t")
        if len(fields) < 7:
            continue

        timestamp, source_ip, destination_ip, source_port, destination_port, protocol, info = fields[:7]

        event = normalize_log_event(
            {
                "timestamp": timestamp,
                "source": "tshark",
                "event": info,
                "level": "INFO",
            },
            source="tshark",
            event_type="network_connection_attempt",
            target=destination_ip,
        )

        event["source_ip"] = source_ip
        event["destination_ip"] = destination_ip
        event["source_port"] = source_port
        event["destination_port"] = destination_port
        event["protocol"] = protocol
        event["message"] = info
        try:
            scoped = _attach_registered_tshark_scope(event)
        except Exception as exc:
            print(f"[SOC TSHARK SCOPE] Ownership lookup failed: {exc}", flush=True)
            continue
        if not scoped:
            print("[SOC TSHARK SCOPE] Event skipped: missing, disabled, or unowned source.", flush=True)
            continue

        detections = evaluate_event(event)

        if detections:
            print(
                f"[SOC NETWORK DETECTION] {source_ip} -> "
                f"{destination_ip}:{destination_port} | {len(detections)} detection(s)",
                flush=True,
            )

            db = SessionLocal()
            try:
                for detection in detections:
                    detection_event = {
                        "event_id": generate_event_id(
                            json.dumps(
                                {
                                    "rule_id": detection["rule_id"],
                                    "group_value": detection["group_value"],
                                    "evidence": detection["evidence"],
                                },
                                sort_keys=True,
                                default=str,
                            )
                        ),
                        "timestamp": event.get("timestamp"),
                        "source": "tshark-siem",
                        "event_type": "network_detection",
                        "severity": detection["severity"],
                        "message": (
                            f"{detection['rule_name']} detected: "
                            f"{detection['event_count']} matching network events "
                            f"from {detection['group_value']}"
                        ),
                        "target": destination_ip,
                        "client_id": event.get("client_id"),
                        "owner_user_id": event.get("owner_user_id"),
                        "_tenant_scope_key": event.get("_tenant_scope_key"),
                        "telemetry_source_id": event.get("telemetry_source_id"),
                        "raw_event": {
                            "rule": detection["rule_id"],
                            "rule_name": detection["rule_name"],
                            "trigger_event": event,
                            "evidence": detection["evidence"],
                            "threshold": detection["threshold"],
                            "window_seconds": detection["window_seconds"],
                            "event_count": detection["event_count"],
                            "group_by": detection["group_by"],
                            "group_value": detection["group_value"],
                            "response_actions": detection["response_actions"],
                        },
                    }

                    stored = store_security_event(db, detection_event)
                    db.commit()
                    notify_security_event(detection_event)

                    print(
                        f"[SOC NETWORK DETECTION] {detection['rule_id']} | "
                        f"{detection['rule_name']} | "
                        f"{detection['group_value']} | "
                        f"{detection['event_count']} events",
                        flush=True,
                    )
            finally:
                db.close()

    process.wait()



def run_tshark_dns_listener():
    """Capture real DNS queries and feed them into the SIEM."""
    command = [
        "sudo", "-n", "/usr/bin/tshark",
        "-i", "any",
        "-l",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "udp.srcport",
        "-e", "tcp.srcport",
        "-e", "udp.dstport",
        "-e", "tcp.dstport",
        "-e", "dns.qry.name",
        "-e", "dns.qry.type",
        "-Y", "dns.flags.response == 0 && dns.qry.name",
    ]

    print("[SOC DNS] Starting real-time DNS query listener...", flush=True)

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    try:
        for raw_line in process.stdout:
            line = raw_line.rstrip("\r\n")
            if not line or line.startswith((
                "Capturing", "Running as user", "tshark:"
            )):
                continue

            fields = line.split("\t")
            if len(fields) < 10:
                continue

            epoch = fields[0].strip()
            source_ip = fields[1].strip() or fields[2].strip()
            destination_ip = fields[3].strip() or fields[4].strip()
            source_port = fields[5].strip() or fields[6].strip()
            destination_port = fields[7].strip() or fields[8].strip()
            query_name = fields[9].strip().lower().rstrip(".")
            query_type = fields[10].strip() if len(fields) > 10 else ""

            if not source_ip or not query_name:
                continue

            try:
                timestamp = datetime.fromtimestamp(
                    float(epoch), timezone.utc
                ).isoformat()
            except (TypeError, ValueError, OSError):
                timestamp = datetime.now(timezone.utc).isoformat()

            message = f"DNS query: {query_name} (type {query_type or 'unknown'})"

            event = normalize_log_event(
                {
                    "timestamp": timestamp,
                    "source": "tshark-dns",
                    "event": message,
                    "level": "INFO",
                },
                source="tshark-dns",
                event_type="dns_query",
                target=destination_ip or None,
                event_id=generate_event_id(line),
            )
            event.update({
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": source_port,
                "destination_port": destination_port,
                "dns_query_name": query_name,
                "dns_query_type": query_type,
                "protocol": "DNS",
                "message": message,
            })

            try:
                scoped = _attach_registered_tshark_scope(event)
            except Exception as exc:
                print(f"[SOC TSHARK SCOPE] Ownership lookup failed: {exc}", flush=True)
                continue
            if not scoped:
                print("[SOC TSHARK SCOPE] Event skipped: missing, disabled, or unowned source.", flush=True)
                continue

            # Persist the structured DNS evidence for investigation.
            original_raw = event.get("raw_event")
            event["raw_event"] = {
                **(original_raw if isinstance(original_raw, dict) else {}),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": source_port,
                "destination_port": destination_port,
                "dns_query_name": query_name,
                "dns_query_type": query_type,
                "protocol": "DNS",
            }

            db = SessionLocal()
            try:
                store_security_event(db, event)
                db.commit()
            except Exception as exc:
                db.rollback()
                print(f"[SOC DNS] Event storage failed: {exc}", flush=True)
                continue
            finally:
                db.close()

            try:
                notify_security_event(event)
            except Exception as exc:
                print(f"[SOC DNS] Event notification failed: {exc}", flush=True)

            detections = evaluate_event(event)

            for detection in detections:
                if detection["rule_id"] != "DNS-001":
                    continue

                detection_event = {
                    "event_id": generate_event_id(json.dumps(
                        {
                            "rule_id": detection["rule_id"],
                            "group_value": detection["group_value"],
                            "evidence": detection["evidence"],
                        },
                        sort_keys=True,
                        default=str,
                    )),
                    "timestamp": event.get("timestamp"),
                    "source": "tshark-dns-siem",
                    "event_type": "dns_detection",
                    "severity": detection["severity"],
                    "message": (
                        f"{detection['rule_name']} detected: "
                        f"{detection['event_count']} DNS queries "
                        f"from {detection['group_value']}"
                    ),
                    "target": destination_ip or None,
                    "client_id": event.get("client_id"),
                        "owner_user_id": event.get("owner_user_id"),
                        "_tenant_scope_key": event.get("_tenant_scope_key"),
                        "telemetry_source_id": event.get("telemetry_source_id"),
                    "raw_event": {
                        "rule": detection["rule_id"],
                        "rule_name": detection["rule_name"],
                        "trigger_event": event,
                        "evidence": detection["evidence"],
                        "threshold": detection["threshold"],
                        "window_seconds": detection["window_seconds"],
                        "event_count": detection["event_count"],
                        "group_by": detection["group_by"],
                        "group_value": detection["group_value"],
                        "response_actions": detection["response_actions"],
                    },
                }

                detection_mappings = map_security_event(detection_event)
                detection_mapping = (
                    detection_mappings[0] if detection_mappings else None
                )

                if detection_mapping:
                    tactics = detection_mapping.get("tactics") or []
                    detection_event["mitre"] = {
                        "technique_id": detection_mapping.get("technique_id"),
                        "technique_name": detection_mapping.get("technique_name"),
                        "tactic": tactics[0] if tactics else None,
                        "mapping_source": detection_mapping.get("mapping_source"),
                        "confidence": detection_mapping.get("confidence"),
                        "evidence": detection_mapping.get("evidence"),
                    }

                detection_db = SessionLocal()
                try:
                    store_security_event(
                        detection_db,
                        detection_event,
                        detection_mapping,
                    )
                    detection_db.commit()
                except Exception as exc:
                    detection_db.rollback()
                    print(f"[SOC DNS] Detection storage failed: {exc}", flush=True)
                    continue
                finally:
                    detection_db.close()

                try:
                    notify_security_event(detection_event)
                except Exception as exc:
                    print(f"[SOC DNS] Detection notification failed: {exc}", flush=True)

                print(
                    f"[SOC DNS DETECTION] {detection['rule_id']} | "
                    f"{detection['rule_name']} | {detection['group_value']} | "
                    f"{detection['event_count']} events",
                    flush=True,
                )
    except Exception as exc:
        print(f"[SOC DNS LISTENER] Error: {exc}", flush=True)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)




def start_listener():
    """Start the real-time SSH and Linux security listeners once."""
    global _listener_thread
    global _linux_listener_thread
    global _tshark_listener_thread
    global _dns_listener_thread

    with _listener_lock:
        if _dns_listener_thread is None or not _dns_listener_thread.is_alive():
            _dns_listener_thread = threading.Thread(
                target=run_tshark_dns_listener,
                name="soc-tshark-dns-listener",
                daemon=True,
            )
            _dns_listener_thread.start()
            print("[SOC DNS LISTENER] Background listener started.", flush=True)

        if _tshark_listener_thread is None or not _tshark_listener_thread.is_alive():
            _tshark_listener_thread = threading.Thread(
                target=run_tshark_security_listener,
                name="soc-tshark-security-listener",
                daemon=True,
            )
            _tshark_listener_thread.start()
            print("[SOC TSHARK LISTENER] Background listener started.", flush=True)

        if _listener_thread is None or not _listener_thread.is_alive():
            _listener_thread = threading.Thread(
                target=run_listener,
                name="soc-realtime-journal-listener",
                daemon=True,
            )
            _listener_thread.start()

            print(
                "[SOC LISTENER] SSH listener started.",
                flush=True,
            )

        if (
            _linux_listener_thread is None
            or not _linux_listener_thread.is_alive()
        ):
            _linux_listener_thread = threading.Thread(
                target=run_linux_security_listener,
                name="soc-linux-security-listener",
                daemon=True,
            )
            _linux_listener_thread.start()

            print(
                "[SOC LINUX LISTENER] Background listener started.",
                flush=True,
            )


if __name__ == "__main__":
    run_listener()