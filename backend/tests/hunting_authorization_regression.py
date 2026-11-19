"""Run directly: isolated hunting authorization regression tests."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import json
    import unittest
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text
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
    import hunting_router
    import rbac

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(hunting_router.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[database.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    class HuntingTests(unittest.TestCase):
        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, username=f"user-{uid}",
                role_id=role, client_id=client,
            )

        def setUp(self):
            for model in (
                models.User, models.TelemetrySource, models.SecurityEvent,
                models.EndpointAsset, models.EndpointProcess,
            ):
                model.__table__.create(engine, checkfirst=True)

            with engine.begin() as connection:
                connection.execute(text(
                    "CREATE TABLE IF NOT EXISTS assessments "
                    "(id INTEGER PRIMARY KEY, user_id INTEGER)"
                ))
                for name in (
                    "endpoint_processes", "endpoint_assets", "security_events",
                    "telemetry_sources", "assessments", "users",
                ):
                    connection.execute(text(f"DELETE FROM {name}"))

            self.now = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=5)
            with Session() as db:
                for uid, client in (
                    (5, None), (6, None),
                    (10, 100), (11, 100), (20, 200),
                ):
                    db.add(models.User(
                        id=uid, username=f"user-{uid}",
                        email=f"{uid}@example.invalid",
                        hashed_password="synthetic-unused",
                        role_id=1, client_id=client,
                    ))
                for eid, owner, client in (
                    (1, 5, None), (2, 6, None),
                    (3, 10, 100), (4, 20, 200),
                ):
                    db.add(models.SecurityEvent(
                        id=eid, event_id=f"hunt-test-{eid}",
                        timestamp=self.now,
                        source="synthetic-test", event_type="dns_query",
                        severity="INFO", message="Synthetic observation",
                        owner_user_id=owner, client_id=client,
                        raw_event=json.dumps({
                            "payload": {
                                "username": f"observed-{owner}",
                                "source_ip": "192.0.2.10",
                                "dns_query_name": "synthetic.example",
                            }
                        }),
                        alert_status="ACTIVE",
                    ))
                    db.add(models.EndpointAsset(
                        id=eid, user_id=owner,
                        endpoint_id=f"synthetic-endpoint-{eid}",
                        hostname=f"host-{eid}", status="UNKNOWN",
                    ))
                    db.add(models.EndpointProcess(
                        id=eid, endpoint_asset_id=eid,
                        pid=100 + eid, name=f"synthetic-{eid}",
                        username=f"observed-{owner}",
                        first_seen=self.now, last_seen=self.now,
                    ))
                db.commit()

            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def fetch(self, kind, **params):
            response = self.client.get(
                f"/hunting/explore/{kind}", params=params
            )
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        def test_personal_views_exclude_other_owners(self):
            for kind in ("users", "processes", "network", "timeline"):
                with self.subTest(kind=kind):
                    data = self.fetch(kind)
                    self.assertEqual([r["id"] for r in data["rows"]], [1])
                    self.assertEqual(data["scope"], "personal")

        def test_same_client_shares_authorized_records(self):
            self.login(11, 100)
            for kind in ("users", "processes", "network", "timeline"):
                with self.subTest(kind=kind):
                    data = self.fetch(kind)
                    self.assertEqual([r["id"] for r in data["rows"]], [3])
                    self.assertEqual(data["scope"], "client")

        def test_other_client_sees_only_own_records(self):
            self.login(20, 200)
            for kind in ("users", "processes", "network", "timeline"):
                with self.subTest(kind=kind):
                    self.assertEqual(
                        [r["id"] for r in self.fetch(kind)["rows"]], [4]
                    )

        def test_wrong_role_is_denied(self):
            self.login(role=3)
            for kind in ("users", "processes", "network", "timeline"):
                with self.subTest(kind=kind):
                    response = self.client.get(f"/hunting/explore/{kind}")
                    self.assertEqual(response.status_code, 403, response.text)

        def test_nested_payload_fields_are_returned(self):
            user = self.fetch("users")["rows"][0]
            network = self.fetch("network")["rows"][0]
            self.assertEqual(user["username"], "observed-5")
            self.assertEqual(network["source_ip"], "192.0.2.10")
            self.assertEqual(network["dns_query"], "synthetic.example")

        def test_message_only_username_is_not_structured_identity(self):
            with Session() as db:
                event = db.get(models.SecurityEvent, 1)
                event.raw_event = "{}"
                event.message = "Session opened for user root"
                db.commit()
            self.assertEqual(self.fetch("users")["rows"], [])
            self.assertEqual(len(self.fetch("timeline")["rows"]), 1)

        def test_event_window_excludes_old_events(self):
            with Session() as db:
                db.get(models.SecurityEvent, 1).timestamp = (
                    self.now - timedelta(days=2)
                )
                db.commit()
            self.assertEqual(self.fetch("timeline", hours=24)["rows"], [])
            self.assertEqual(len(self.fetch("timeline", hours=168)["rows"]), 1)

        def test_process_inventory_is_not_filtered_by_event_window(self):
            with Session() as db:
                db.get(models.EndpointProcess, 1).last_seen = (
                    self.now - timedelta(days=60)
                )
                db.commit()
            data = self.fetch("processes", hours=24)
            self.assertEqual(len(data["rows"]), 1)
            self.assertIsNone(data["window_start"])

        def test_search_cannot_reveal_other_owner(self):
            for kind in ("users", "processes", "network", "timeline"):
                with self.subTest(kind=kind):
                    data = self.fetch(kind, search="observed-6")
                    self.assertEqual(data["rows"], [])

        def test_search_matches_recorded_fields(self):
            self.assertEqual(
                len(self.fetch("users", search="OBSERVED-5")["rows"]), 1
            )
            self.assertEqual(
                len(self.fetch("processes", search="synthetic-1")["rows"]), 1
            )
            self.assertEqual(
                len(self.fetch("network", search="192.0.2.10")["rows"]), 1
            )

        def test_network_view_excludes_non_network_events(self):
            with Session() as db:
                db.get(models.SecurityEvent, 1).event_type = "privileged_command"
                db.commit()
            self.assertEqual(self.fetch("network")["rows"], [])
            self.assertEqual(len(self.fetch("timeline")["rows"]), 1)

        def test_invalid_view_and_parameters(self):
            for suffix, status in (
                ("unknown", 404),
                ("timeline?hours=0", 422),
                ("timeline?hours=8761", 422),
                ("timeline?search=" + "a" * 201, 422),
            ):
                with self.subTest(suffix=suffix):
                    response = self.client.get("/hunting/explore/" + suffix)
                    self.assertEqual(response.status_code, status, response.text)


        def summary(self, **params):
            response = self.client.get(
                "/hunting/identity-summary", params=params
            )
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        def test_identity_summary_counts_beyond_500(self):
            with Session() as db:
                db.get(models.SecurityEvent, 1).event_type = "authentication_session"
                db.get(models.SecurityEvent, 2).event_type = "authentication_session"
                for index in range(501):
                    db.add(models.SecurityEvent(
                        id=1000 + index,
                        event_id=f"identity-bulk-{index}",
                        timestamp=self.now,
                        source="synthetic-test",
                        event_type="privileged_command",
                        severity="INFO",
                        message="Synthetic privileged event",
                        owner_user_id=5,
                        raw_event="{}",
                        alert_status="ACTIVE",
                    ))
                db.commit()
            data = self.summary()
            self.assertEqual(data["authentication_records"], 1)
            self.assertEqual(data["privileged_records"], 501)
            self.assertEqual(data["total_events"], 502)
            self.assertEqual(len(data["recent_events"]), 10)

        def test_identity_summary_same_client_scope(self):
            with Session() as db:
                for event in db.query(models.SecurityEvent).all():
                    event.event_type = "authentication_session"
                db.commit()
            self.login(11, 100)
            data = self.summary()
            self.assertEqual(data["scope"], "client")
            self.assertEqual(data["authentication_records"], 1)
            self.assertEqual(
                [row["id"] for row in data["recent_events"]], [3]
            )

        def test_identity_summary_window(self):
            with Session() as db:
                event = db.get(models.SecurityEvent, 1)
                event.event_type = "authentication_session"
                event.timestamp = self.now - timedelta(days=2)
                db.commit()
            self.assertEqual(self.summary(hours=24)["total_events"], 0)
            self.assertEqual(self.summary(hours=168)["total_events"], 1)
            self.assertEqual(self.summary(hours=0)["total_events"], 1)

        def test_identity_summary_wrong_role_denied(self):
            self.login(role=3)
            response = self.client.get("/hunting/identity-summary")
            self.assertEqual(response.status_code, 403, response.text)


    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HuntingTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    engine.dispose()
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
