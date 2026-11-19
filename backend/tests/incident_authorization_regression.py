"""Run directly in its own process; uses only an in-memory database."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import unittest
    from datetime import datetime, timezone
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
    import incident
    import rbac

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(incident.router)

    def test_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[database.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    class AuthorizationTests(unittest.TestCase):
        def login(self, uid, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, username=f"user-{uid}",
                role_id=role, client_id=client,
            )

        def setUp(self):
            for table in (
                models.User.__table__, models.TelemetrySource.__table__,
                models.SecurityEvent.__table__, incident.Incident.__table__,
                incident.IncidentHistory.__table__,
            ):
                table.create(engine, checkfirst=True)

            with engine.begin() as connection:
                connection.execute(text(
                    "CREATE TABLE IF NOT EXISTS assessments "
                    "(id INTEGER PRIMARY KEY, user_id INTEGER)"
                ))
                for name in (
                    "incident_history", "incidents", "security_events",
                    "telemetry_sources", "assessments", "users",
                ):
                    connection.execute(text(f"DELETE FROM {name}"))

            db = Session()
            try:
                for uid, client in ((5, None), (6, None), (10, 100),
                                    (11, 100), (20, 200)):
                    db.add(models.User(
                        id=uid, username=f"user-{uid}",
                        email=f"user-{uid}@example.invalid",
                        hashed_password="synthetic-unused",
                        role_id=1, client_id=client,
                    ))
                db.add(models.TelemetrySource(
                    id=25, name="Synthetic", client_id=100,
                    owner_user_id=10, token_hash="synthetic-unused-token",
                    enabled=True, created_by=10,
                ))
                db.execute(text(
                    "INSERT INTO assessments (id,user_id) VALUES (77,10)"
                ))
                db.commit()

                records = {
                    900001: {"owner_user_id": 5},
                    910001: {"client_id": 100, "owner_user_id": 10},
                    910002: {"telemetry_source_id": 25},
                    910003: {"assessment_id": 77},
                }
                for eid, ownership in records.items():
                    db.add(models.SecurityEvent(
                        id=eid, event_id=f"synthetic-{eid}",
                        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
                        source="tshark-siem", event_type="network_detection",
                        severity="HIGH", message="Synthetic authorization test",
                        alert_status="ACTIVE", raw_event='{"evidence":[]}',
                        **ownership,
                    ))
                db.commit()
                for eid in records:
                    db.add(incident.Incident(
                        incident_id=f"INC-{eid}", security_event_id=eid,
                        title="Synthetic case", severity="HIGH",
                        status="IN_PROGRESS",
                    ))
                db.commit()
            finally:
                db.close()
            self.login(5)
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def listing(self):
            response = self.client.get("/incidents/", params={
                "include_unmapped_network": True,
                "include_summary": True, "page_size": 25,
            })
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        def reads(self, ids, expected):
            for eid in ids:
                for suffix in (
                    "?include_unmapped_network=true", "/case", "/history"
                ):
                    with self.subTest(event=eid, suffix=suffix):
                        response = self.client.get(f"/incidents/INC-{eid}{suffix}")
                        self.assertEqual(response.status_code, expected, response.text)

        def denied_mutations(self, ids):
            actions = [
                ("post", "/case?include_unmapped_network=true", {}),
                ("patch", "/case/start", {}),
                ("patch", "/case/contain", {}),
                ("patch", "/case/assign?assigned_to=user-5", {}),
                ("patch", "/case/notes", {"notes": "Unauthorized"}),
                ("patch", "/case/resolve", {"resolution": "Unauthorized"}),
                ("patch", "/case/close", {}),
            ]
            for eid in ids:
                for method, suffix, payload in actions:
                    with self.subTest(event=eid, action=suffix):
                        response = getattr(self.client, method)(
                            f"/incidents/INC-{eid}{suffix}", json=payload
                        )
                        self.assertEqual(response.status_code, 404, response.text)
            db = Session()
            try:
                self.assertEqual(db.query(incident.IncidentHistory).count(), 0)
                for case in db.query(incident.Incident).all():
                    self.assertEqual(case.status, "IN_PROGRESS")
                    self.assertIsNone(case.investigation_notes)
            finally:
                db.close()

        def test_owner_can_read(self):
            self.assertEqual(self.listing()["total"], 1)
            self.reads([900001], 200)

        def test_other_user_empty_list(self):
            self.login(6)
            result = self.listing()
            self.assertEqual(result["incidents"], [])
            self.assertEqual(result["summary"]["Total"], 0)

        def test_other_user_cannot_read(self):
            self.login(6)
            self.reads([900001], 404)

        def test_other_user_cannot_mutate(self):
            self.login(6)
            self.denied_mutations([900001])

        def test_wrong_role_denied(self):
            self.login(5, role=3)
            response = self.client.get("/incidents/INC-900001")
            self.assertEqual(response.status_code, 403)

        def test_same_client_lists_three_ownership_paths(self):
            self.login(11, 100)
            result = self.listing()
            self.assertEqual(result["total"], 3)
            self.assertEqual(result["summary"]["Total"], 3)

        def test_same_client_can_read(self):
            self.login(11, 100)
            self.reads(range(910001, 910004), 200)

        def test_same_client_update_records_actor(self):
            self.login(11, 100)
            response = self.client.patch(
                "/incidents/INC-910001/case/notes",
                json={"notes": "Synthetic authorized update"},
            )
            self.assertEqual(response.status_code, 200, response.text)
            history = self.client.get(
                "/incidents/INC-910001/history"
            ).json()["history"]
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["actor_username"], "user-11")
            self.assertEqual(history[0]["action"], "NOTES_UPDATED")

        def test_other_client_cannot_list_or_read(self):
            self.login(20, 200)
            result = self.listing()
            self.assertEqual(result["total"], 0)
            self.assertEqual(result["summary"]["Total"], 0)
            self.reads(range(910001, 910004), 404)

        def test_other_client_cannot_mutate(self):
            self.login(20, 200)
            self.denied_mutations(range(910001, 910004))

        def test_other_client_assignee_rejected(self):
            self.login(11, 100)
            response = self.client.patch(
                "/incidents/INC-910001/case/assign",
                params={"assigned_to": "user-20"}, json={},
            )
            self.assertEqual(response.status_code, 400, response.text)

    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(AuthorizationTests)
    )
    engine.dispose()
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
