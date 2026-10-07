from database import SessionLocal

from journal_ingestion import read_new_journal_events
from journal_state import save_cursor
from logs import filter_auth_logs, format_journal_logs
from mitre_mapper import map_security_event
from security_correlation import correlate_authentication_events
from security_event_store import store_security_event
from security_events import (
    generate_event_id,
    normalize_log_event,
)


def process_new_security_events():
    """
    Process new journal events through the SOC pipeline.

    The journal cursor is advanced only after the complete
    processing transaction succeeds.
    """

    journal_events, latest_cursor = (
        read_new_journal_events()
    )

    if not journal_events:
        return {
            "journal_events": 0,
            "authentication_events": 0,
            "correlations": 0,
            "stored_events": 0,
            "cursor_saved": False,
        }

    auth_lines = filter_auth_logs(
        journal_events
    )

    logs = format_journal_logs(
        auth_lines,
        "auth",
    )

    events = []

    for log, raw_line in zip(
        logs,
        auth_lines,
    ):
        event = normalize_log_event(
            log,
            source="systemd-journald",
            event_type="authentication",
            event_id=generate_event_id(
                raw_line
            ),
        )

        events.append(event)

    correlations = correlate_authentication_events(
        events,
        window_seconds=60,
    )

    db = SessionLocal()

    stored_events = 0

    try:
        for correlation in correlations:
            for event in correlation["events"]:

                mappings = map_security_event(
                    event
                )

                if mappings:
                    for mapping in mappings:
                        store_security_event(
                            db,
                            event,
                            mapping,
                        )
                        stored_events += 1

                else:
                    store_security_event(
                        db,
                        event,
                    )
                    stored_events += 1

        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

    if latest_cursor:
        save_cursor(latest_cursor)

    return {
        "journal_events": len(
            journal_events
        ),
        "authentication_events": len(
            events
        ),
        "correlations": len(
            correlations
        ),
        "stored_events": stored_events,
        "cursor_saved": bool(
            latest_cursor
        ),
    }


if __name__ == "__main__":
    result = process_new_security_events()

    for key, value in result.items():
        print(
            f"{key}: {value}"
        )