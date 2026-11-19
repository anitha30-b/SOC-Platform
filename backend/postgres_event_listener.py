import json
import select
import threading

import psycopg2

from database import DATABASE_URL
from realtime_broadcaster import security_event_broadcaster
from client_realtime_events import client_siem_event_broadcaster
from notification_service import create_notification, create_alert_notifications_for_event
from incident import create_incidents_for_event


class PostgreSQLEventListener:
    """
    Listen for PostgreSQL security_events notifications.

    Automatically reconnects after connection failures.
    Existing database notification creation and WebSocket
    event broadcasting are preserved.
    """

    def __init__(self):
        self.connection = None
        self.thread = None
        self.stop_event = threading.Event()
        self._start_lock = threading.Lock()

    def connect(self):
        connection_string = DATABASE_URL.replace(
            "postgresql+psycopg2://",
            "postgresql://",
            1,
        )

        connection = psycopg2.connect(connection_string)

        connection.set_isolation_level(
            psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT
        )

        cursor = connection.cursor()
        cursor.execute("LISTEN security_events;")
        cursor.close()

        print(
            "[SOC PG LISTENER] Connected and listening "
            "on security_events.",
            flush=True,
        )

        return connection

    def process_notification(self, notification):
        try:
            event = json.loads(notification.payload)

            print(
                "[SOC PG LISTENER] Received event: "
                f"{event.get('event_id')}",
                flush=True,
            )

        except (json.JSONDecodeError, TypeError) as exc:
            print(
                "[SOC PG LISTENER] Invalid notification payload: "
                f"{exc}",
                flush=True,
            )
            return

        # Notification creation must not prevent event broadcasting.
        try:
            create_notification(event)
        except Exception as exc:
            print(
                "[SOC PG LISTENER] Notification creation failed: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

        # Process alert notifications independently of event notifications.
        try:
            count = create_alert_notifications_for_event(event)
            if count:
                print(
                    "[SOC PG LISTENER] Alert notifications processed: "
                    f"{count}",
                    flush=True,
                )
        except Exception as exc:
            print(
                "[SOC PG LISTENER] Alert notification creation failed: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

        # Automatically create or update an incident for qualifying alerts.
        try:
            result = create_incidents_for_event(event)

            if result.get("created") or result.get("linked"):
                print(
                    "[SOC INCIDENT ENGINE] "
                    f"Created={result.get('created')}; "
                    f"Linked={result.get('linked')}; "
                    f"Incident={result.get('incident_id')}",
                    flush=True,
                )

        except Exception as exc:
            print(
                "[SOC INCIDENT ENGINE] Incident creation failed: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

        try:
            security_event_broadcaster.publish(event)
        except Exception as exc:
            print(
                "[SOC PG LISTENER] Event broadcast failed: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

        # Tenant sockets receive IDs only and independently check ownership.
        event_id = str(event.get("event_id") or "").strip()
        if event_id:
            try:
                client_siem_event_broadcaster.publish({"event_id": event_id})
            except Exception as exc:
                print(f"[SOC PG LISTENER] Client refresh failed: {exc}", flush=True)

    def run(self):
        retry_delays = (1, 2, 5, 10, 30)
        retry_index = 0

        while not self.stop_event.is_set():
            connection = None

            try:
                connection = self.connect()
                self.connection = connection
                retry_index = 0

                while not self.stop_event.is_set():
                    ready = select.select(
                        [connection],
                        [],
                        [],
                        1,
                    )

                    if not ready[0]:
                        continue

                    connection.poll()

                    while connection.notifies:
                        notification = connection.notifies.pop(0)
                        self.process_notification(notification)

            except Exception as exc:
                if not self.stop_event.is_set():
                    print(
                        "[SOC PG LISTENER] Connection/listener error: "
                        f"{type(exc).__name__}: {exc}",
                        flush=True,
                    )

            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass

                if self.connection is connection:
                    self.connection = None

            if self.stop_event.is_set():
                break

            delay = retry_delays[
                min(retry_index, len(retry_delays) - 1)
            ]

            print(
                f"[SOC PG LISTENER] Reconnecting in {delay} seconds...",
                flush=True,
            )

            self.stop_event.wait(delay)
            retry_index = min(
                retry_index + 1,
                len(retry_delays) - 1,
            )

        print(
            "[SOC PG LISTENER] Listener stopped.",
            flush=True,
        )

    def start(self):
        with self._start_lock:
            if self.thread and self.thread.is_alive():
                print(
                    "[SOC PG LISTENER] Already running.",
                    flush=True,
                )
                return

            self.stop_event.clear()

            self.thread = threading.Thread(
                target=self.run,
                name="SOC-PostgreSQL-Event-Listener",
                daemon=True,
            )

            self.thread.start()

    def stop(self):
        self.stop_event.set()

        thread = self.thread

        if thread and thread.is_alive():
            thread.join(timeout=5)

        if thread and thread.is_alive():
            print(
                "[SOC PG LISTENER] Shutdown is still waiting "
                "for the listener thread.",
                flush=True,
            )


postgres_event_listener = PostgreSQLEventListener()
