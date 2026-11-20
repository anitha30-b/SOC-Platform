"""Security Events HTTP tests with actual models and ownership rules."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import unittest
    from datetime import datetime, date
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    import database

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    database.engine.dispose()
    database.engine = engine
    assert engine.url.get_backend_name() == "sqlite"

    import models
    import rbac
    import security_events_router as events

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(events.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[events.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    tables = [
        models.User.__table__,
        models.Assessment.__table__,
        models.TelemetrySource.__table__,
        models.SecurityEvent.__table__,
        models.DetectionResult.__table__,
    ]
    for table in tables:
        table.create(engine, checkfirst=True)

    def insert_fixture(connection, table, **values):
        # Populate unrelated required fields with synthetic values.
        # Explicit ownership fields below determine every test's scope.
        marker = values.get("id", "fixture")
        for column in table.columns:
            if (
                column.name in values
                or column.nullable
                or column.primary_key
                or column.default is not None
                or column.server_default is not None
            ):
                continue

            try:
                kind = column.type.python_type
            except (AttributeError, NotImplementedError):
                raise AssertionError(
                    f"Explicit fixture needed: {table.name}.{column.name}"
                )

            if kind is str:
                values[column.name] = f"test-{column.name}-{marker}"
            elif kind is datetime:
                values[column.name] = datetime(2026, 1, 1)
            elif kind is date:
                values[column.name] = date(2026, 1, 1)
            elif kind is bool:
                values[column.name] = False
            elif kind is int:
                values[column.name] = 0
            elif kind is float:
                values[column.name] = 0.0
            elif kind is dict:
                values[column.name] = {}
            elif kind is list:
                values[column.name] = []
            else:
                raise AssertionError(
                    f"Explicit fixture needed: {table.name}.{column.name}"
                )
        connection.execute(table.insert().values(**values))

    class EventTests(unittest.TestCase):
        PERSONAL = {"personal-owner", "personal-assessment", "personal-source"}
        CLIENT = {
            "client-owner", "client-assessment", "client-explicit", "client-source"
        }

        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, client_id=client, role_id=role,
                username=f"user-{uid}",
            )

        def setUp(self):
            with engine.begin() as connection:
                for table in reversed(tables):
                    connection.execute(table.delete())

                for uid, client in (
                    (5, None), (6, None), (10, 100), (11, 100), (20, 200),
                ):
                    insert_fixture(
                        connection, models.User.__table__,
                        id=uid, username=f"user-{uid}",
                        client_id=client, role_id=1,
                    )
                    insert_fixture(
                        connection, models.Assessment.__table__,
                        id=uid * 100, user_id=uid,
                    )

                for source_id, owner, client in (
                    (50, 5, None), (100, 11, 100), (200, 20, 200),
                ):
                    insert_fixture(
                        connection, models.TelemetrySource.__table__,
                        id=source_id, owner_user_id=owner, client_id=client,
                    )

                fixtures = [
                    ("personal-owner", {"owner_user_id": 5}),
                    ("personal-assessment", {"assessment_id": 500}),
                    ("personal-source", {"telemetry_source_id": 50}),
                    ("peer-personal", {"owner_user_id": 6}),
                    ("client-owner", {"owner_user_id": 10, "client_id": 100}),
                    ("client-assessment", {"assessment_id": 1100}),
                    ("client-explicit", {"client_id": 100}),
                    ("client-source", {"telemetry_source_id": 100}),
                    ("foreign-client", {
                        "owner_user_id": 20, "client_id": 200,
                        "assessment_id": 2000, "telemetry_source_id": 200,
                    }),
                    ("unowned", {}),
                ]
                for index, (event_id, scope) in enumerate(fixtures, start=1):
                    insert_fixture(
                        connection, models.SecurityEvent.__table__,
                        id=index, event_id=event_id,
                        owner_user_id=scope.get("owner_user_id"),
                        client_id=scope.get("client_id"),
                        assessment_id=scope.get("assessment_id"),
                        telemetry_source_id=scope.get("telemetry_source_id"),
                        source="synthetic",
                        event_type="synthetic_detection",
                        severity="HIGH",
                        message=f"Test event {event_id}",
                        timestamp=datetime(2026, 1, 1, 0, 0, index),
                        mitre_technique_id="T1110",
                        mitre_technique_name="Brute Force",
                        mitre_tactic="credential-access",
                        alert_status="ACTIVE",
                    )

            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def listed_ids(self, **params):
            response = self.client.get("/security-events", params=params)
            self.assertEqual(response.status_code, 200, response.text)
            return {row["event_id"] for row in response.json()}

        def action(self, event_id, action):
            return self.client.patch(f"/security-events/{event_id}/{action}")

        def test_personal_scope_includes_all_three_ownership_links(self):
            self.assertEqual(self.listed_ids(limit=500), self.PERSONAL)

        def test_same_client_sharing_is_preserved(self):
            self.login(10, 100)
            self.assertEqual(self.listed_ids(limit=500), self.CLIENT)
            self.login(11, 100)
            # Directly owned events remain available through their own
            # ownership links; both users can read these client fixtures.
            self.assertEqual(self.listed_ids(limit=500), self.CLIENT)

        def test_other_client_only_sees_its_events(self):
            self.login(20, 200)
            self.assertEqual(self.listed_ids(), {"foreign-client"})

        def test_unowned_event_is_not_visible(self):
            for uid, client in ((5, None), (10, 100), (20, 200)):
                self.login(uid, client)
                self.assertNotIn("unowned", self.listed_ids())

        def test_filters_do_not_bypass_ownership(self):
            self.assertEqual(
                self.listed_ids(
                    search="foreign-client", severity="HIGH",
                    source="synthetic", mitre_technique="T1110",
                ),
                set(),
            )
            self.assertEqual(
                self.listed_ids(event_type="synthetic_detection"),
                self.PERSONAL,
            )

        def test_recent_and_active_alert_lists_remain_scoped(self):
            for path, key in (
                ("/security-events/stats/recent", "events"),
                ("/security-events/stats/active-alerts", "alerts"),
            ):
                response = self.client.get(path, params={"limit": 50})
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(
                    {row["event_id"] for row in response.json()[key]},
                    self.PERSONAL,
                )

        def test_technique_and_tactic_counts_are_scoped(self):
            for path, key in (
                ("/security-events/stats/techniques", "techniques"),
                ("/security-events/stats/tactics", "tactics"),
            ):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200, response.text)
                rows = response.json()[key]
                self.assertEqual(sum(row["event_count"] for row in rows), 3)

        def test_foreign_and_unowned_events_cannot_be_mutated(self):
            for event_id in ("peer-personal", "foreign-client", "unowned"):
                for action in ("acknowledge", "resolve", "suppress", "unsuppress"):
                    response = self.action(event_id, action)
                    self.assertEqual(response.status_code, 404, response.text)
            with Session() as db:
                for event_id in ("peer-personal", "foreign-client", "unowned"):
                    row = db.query(models.SecurityEvent).filter_by(
                        event_id=event_id
                    ).one()
                    self.assertEqual(row.alert_status, "ACTIVE")

        def test_owner_acknowledge_then_resolve(self):
            response = self.action("personal-owner", "acknowledge")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["alert"]["alert_status"], "ACKNOWLEDGED")
            self.assertIsNotNone(response.json()["alert"]["acknowledged_at"])

            response = self.action("personal-owner", "resolve")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["alert"]["alert_status"], "RESOLVED")
            self.assertIsNotNone(response.json()["alert"]["resolved_at"])

        def test_same_client_can_change_shared_event(self):
            self.login(10, 100)
            response = self.action("client-assessment", "acknowledge")
            self.assertEqual(response.status_code, 200, response.text)
            self.login(11, 100)
            response = self.action("client-assessment", "resolve")
            self.assertEqual(response.status_code, 200, response.text)

        def test_invalid_transitions_are_rejected(self):
            self.assertEqual(self.action("personal-owner", "resolve").status_code, 400)
            self.assertEqual(self.action("personal-owner", "acknowledge").status_code, 200)
            self.assertEqual(self.action("personal-owner", "acknowledge").status_code, 400)
            self.assertEqual(self.action("personal-owner", "resolve").status_code, 200)
            self.assertEqual(self.action("personal-owner", "resolve").status_code, 400)

        def test_suppress_and_unsuppress(self):
            response = self.action("personal-source", "suppress")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["alert"]["alert_status"], "SUPPRESSED")
            response = self.action("personal-source", "unsuppress")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["alert"]["alert_status"], "ACTIVE")

        def test_invalid_limit_is_rejected(self):
            for limit in (0, 501):
                response = self.client.get(
                    "/security-events", params={"limit": limit}
                )
                self.assertEqual(response.status_code, 422, response.text)

        def test_wrong_role_is_denied(self):
            self.login(role=3)
            for path in (
                "/security-events",
                "/security-events/stats/recent",
                "/security-events/stats/active-alerts",
                "/security-events/stats/techniques",
                "/security-events/stats/tactics",
            ):
                self.assertEqual(self.client.get(path).status_code, 403)
            for action in ("acknowledge", "resolve", "suppress", "unsuppress"):
                self.assertEqual(
                    self.action("personal-owner", action).status_code, 403
                )


        def run_database_scoped_websocket(self, uid, event_id):
            import asyncio
            import json
            from unittest.mock import patch
            from starlette.websockets import WebSocketDisconnect
            import client_realtime_events as realtime

            async def run():
                class SignalQueue:
                    def __init__(self):
                        self.signals = [
                            json.dumps({"event_id": event_id})
                        ]

                    async def get(self):
                        if self.signals:
                            return self.signals.pop(0)
                        # End the route deterministically after one signal.
                        raise WebSocketDisconnect(code=1000)

                class Broadcaster:
                    def __init__(self):
                        self.queue = SignalQueue()
                        self.subscribed = False
                        self.unsubscribed = False

                    def subscribe(self):
                        self.subscribed = True
                        return self.queue

                    def unsubscribe(self, queue):
                        if queue is not self.queue:
                            raise AssertionError("Unexpected subscription")
                        self.unsubscribed = True

                class Socket:
                    def __init__(self):
                        self.query_params = {"token": "test-token"}
                        self.accepted = False
                        self.messages = []
                        self.close_codes = []

                    async def accept(self):
                        self.accepted = True

                    async def receive_text(self):
                        await asyncio.Event().wait()

                    async def send_json(self, data):
                        self.messages.append(data)

                    async def close(self, code=1000, reason=None):
                        self.close_codes.append(code)

                broadcaster = Broadcaster()
                socket = Socket()

                # Actual ORM users, persisted events and ownership filter.
                # Only token decoding and signal transport are substituted.
                with patch.object(
                    realtime, "SessionLocal", Session
                ), patch.object(
                    realtime, "decode_access_token",
                    return_value={"sub": str(uid)},
                ), patch.object(
                    realtime, "client_siem_event_broadcaster", broadcaster,
                ):
                    await asyncio.wait_for(
                        realtime.client_siem_events_websocket(socket),
                        timeout=3,
                    )

                if broadcaster.subscribed:
                    self.assertTrue(broadcaster.unsubscribed)
                self.assertNotIn(1011, socket.close_codes)
                return socket

            return asyncio.run(run())

        def test_websocket_personal_owner_gets_minimal_signal(self):
            for event_id in (
                "personal-owner", "personal-assessment", "personal-source"
            ):
                with self.subTest(event_id=event_id):
                    socket = self.run_database_scoped_websocket(5, event_id)
                    self.assertTrue(socket.accepted)
                    self.assertEqual(
                        socket.messages, [{"type": "siem_refresh"}]
                    )

        def test_websocket_same_client_gets_shared_signals(self):
            for event_id in (
                "client-assessment", "client-explicit", "client-source"
            ):
                with self.subTest(event_id=event_id):
                    socket = self.run_database_scoped_websocket(10, event_id)
                    self.assertTrue(socket.accepted)
                    self.assertEqual(
                        socket.messages, [{"type": "siem_refresh"}]
                    )

        def test_websocket_cross_account_and_unowned_signals_are_hidden(self):
            for uid, event_id in (
                (5, "peer-personal"),
                (5, "foreign-client"),
                (10, "foreign-client"),
                (20, "client-explicit"),
                (5, "unowned"),
                (10, "unowned"),
                (5, "missing-event"),
            ):
                with self.subTest(uid=uid, event_id=event_id):
                    socket = self.run_database_scoped_websocket(uid, event_id)
                    self.assertTrue(socket.accepted)
                    self.assertEqual(socket.messages, [])

        def test_websocket_rejects_wrong_role_from_database(self):
            with Session() as db:
                db.query(models.User).filter_by(id=5).one().role_id = 3
                db.commit()
            socket = self.run_database_scoped_websocket(5, "personal-owner")
            self.assertFalse(socket.accepted)
            self.assertEqual(socket.messages, [])
            self.assertIn(1008, socket.close_codes)

        def test_websocket_rejects_missing_database_user(self):
            socket = self.run_database_scoped_websocket(99999, "personal-owner")
            self.assertFalse(socket.accepted)
            self.assertEqual(socket.messages, [])
            self.assertIn(1008, socket.close_codes)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EventTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
