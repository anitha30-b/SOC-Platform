import json
import subprocess
from datetime import datetime, timedelta

import psycopg2

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
from security_events import (
    generate_event_id,
    normalize_log_event,
)


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
        DATABASE_URL.replace("postgresql+psycopg2://", "postgresql://", 1)
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

    if detection_type == "brute_force":
        fingerprint = (
            detection_type,
            usernames,
            source_ips,
            correlation.get(
                "start_time"
            ),
        )
    else:
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
            },
        }

        detection_events.append(
            (
                detection_event,
                mapping,
            )
        )

    return detection_events


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


if __name__ == "__main__":
    run_listener()