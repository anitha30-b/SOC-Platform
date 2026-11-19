import asyncio
import json
import select
import threading

import psycopg2

from database import DATABASE_URL
from client_realtime_events import client_siem_event_broadcaster
from notification_service import create_notification


class PostgreSQLEventListener:
    """
    Listen for PostgreSQL security_events notifications
    and forward them to the in-process WebSocket broadcaster.
    """

    def __init__(self):
        self.connection = None
        self.thread = None
        self.running = False

    def connect(self):
        self.connection = psycopg2.connect(
            DATABASE_URL
        )

        self.connection.set_isolation_level(
            psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT
        )

        cursor = self.connection.cursor()

        cursor.execute(
            "LISTEN security_events;"
        )

        cursor.close()

        print(
            "[SOC PG LISTENER] "
            "Listening on security_events...",
            flush=True,
        )

    def run(self):
        self.connect()

        self.running = True

        while self.running:
            ready = select.select(
                [self.connection],
                [],
                [],
                1,
            )

            if not ready[0]:
                continue

            self.connection.poll()

            while self.connection.notifies:
                notification = (
                    self.connection.notifies.pop(0)
                )

                try:
                    event = json.loads(
                        notification.payload
                    )

                    print(
                        "[SOC PG LISTENER] "
                        f"Received event: "
                        f"{event.get('event_id')}",
                        flush=True,
                    )

                    # Create a persistent Admin notification
                    # from the same real-time security event.
                    create_notification(event)

                    # Publish only a minimal signal. Each connected SIEM
                    # WebSocket independently verifies persisted event ownership.
                    event_id = str(event.get("event_id") or "").strip()
                    if event_id:
                        client_siem_event_broadcaster.publish({
                            "event_id": event_id,
                        })

                except json.JSONDecodeError:
                    print(
                        "[SOC PG LISTENER] "
                        "Invalid notification payload.",
                        flush=True,
                    )

    def start(self):
        self.thread = threading.Thread(
            target=self.run,
            daemon=True,
        )

        self.thread.start()

    def stop(self):
        self.running = False

        if self.connection:
            self.connection.close()


postgres_event_listener = (
    PostgreSQLEventListener()
)