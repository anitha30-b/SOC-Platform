"""Run directly: isolated IOC route authorization regression tests."""
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
    import ioc_router
    import rbac

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(ioc_router.router)

    def test_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[database.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    class IOCAuthorizationTests(unittest.TestCase):
        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, username=f"user-{uid}",
                role_id=role, client_id=client,
            )

        def setUp(self):
            for table in (
                models.User.__table__,
                models.TelemetrySource.__table__,
                models.SecurityEvent.__table__,
                models.IOCIndicator.__table__,
                models.AuditLog.__table__,
            ):
                table.create(engine, checkfirst=True)

            with engine.begin() as connection:
                connection.execute(text(
                    "CREATE TABLE IF NOT EXISTS assessments "
                    "(id INTEGER PRIMARY KEY, user_id INTEGER)"
                ))
                for name in (
                    "audit_logs", "ioc_indicators", "security_events",
                    "telemetry_sources", "assessments", "users",
                ):
                    connection.execute(text(f"DELETE FROM {name}"))

            db = Session()
            try:
                for uid, client in ((5, None), (6, None),
                                    (10, 100), (11, 100), (20, 200)):
                    db.add(models.User(
                        id=uid, username=f"user-{uid}",
                        email=f"user-{uid}@example.invalid",
                        hashed_password="synthetic-unused",
                        role_id=1, client_id=client,
                    ))

                # Two personal indicators, one same-client indicator,
                # and one separate-client indicator.
                for iid, kind, value, owner, client in (
                    (1, "URL", "https://secuzity.example/", 5, None),
                    (2, "SHA256", "a" * 64, 5, None),
                    (3, "URL", "https://client.example/", 10, 100),
                    (4, "IP", "192.0.2.20", 20, 200),
                ):
                    db.add(models.IOCIndicator(
                        id=iid, indicator_type=kind, value=value,
                        created_by=owner, client_id=client,
                        severity="HIGH", confidence=50,
                        enabled=True, source="Synthetic test",
                    ))

                for eid, owner, client, url in (
                    (1, 5, None, "https://secuzity.example/"),
                    (2, 6, None, "https://secuzity.example/"),
                    (3, 10, 100, "https://client.example/"),
                    (4, 20, 200, "https://client.example/"),
                ):
                    db.add(models.SecurityEvent(
                        id=eid, event_id=f"ioc-test-{eid}",
                        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
                        source="synthetic-test", event_type="url_observed",
                        severity="INFO", message=f"Visited {url}",
                        owner_user_id=owner, client_id=client,
                        raw_event="{}", alert_status="ACTIVE",
                    ))
                db.commit()
            finally:
                db.close()

            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def get_json(self, path, **params):
            response = self.client.get(path, params=params)
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        def test_personal_summary_excludes_other_owners(self):
            data = self.get_json("/ioc/registry-summary")
            self.assertEqual(data["total"], 2)
            self.assertEqual(data["enabled"], 2)
            self.assertEqual(data["by_type"]["URL"], 1)
            self.assertEqual(data["by_type"]["SHA256"], 1)

        def test_registry_filters_before_pagination(self):
            data = self.get_json(
                "/ioc/registry", indicator_type="URL", page_size=1
            )
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["count"], 1)
            self.assertEqual(data["indicators"][0]["id"], 1)

        def test_hash_filter_returns_hashes_only(self):
            data = self.get_json("/ioc/registry", indicator_type="HASH")
            self.assertEqual(data["total"], 1)
            self.assertEqual(data["indicators"][0]["indicator_type"], "SHA256")

        def test_other_personal_user_cannot_match_or_delete(self):
            self.login(6)
            self.assertEqual(self.get_json("/ioc/registry")["total"], 0)
            for method, path in (
                ("get", "/ioc/indicators/1/matches"),
                ("delete", "/ioc/indicators/1"),
            ):
                with self.subTest(action=method):
                    response = getattr(self.client, method)(path)
                    self.assertEqual(response.status_code, 404, response.text)

        def test_personal_matches_exclude_other_user_events(self):
            data = self.get_json("/ioc/indicators/1/matches")
            self.assertEqual(data["events_scanned"], 1)
            self.assertEqual(data["candidate_match_count"], 1)

        def test_same_client_can_read_and_match(self):
            self.login(11, 100)
            self.assertEqual(self.get_json("/ioc/registry-summary")["total"], 1)
            data = self.get_json("/ioc/indicators/3/matches")
            self.assertEqual(data["events_scanned"], 1)
            self.assertEqual(data["candidate_match_count"], 1)

        def test_other_client_cannot_match_or_delete(self):
            self.login(20, 200)
            data = self.get_json("/ioc/registry")
            self.assertEqual([item["id"] for item in data["indicators"]], [4])
            for method, path in (
                ("get", "/ioc/indicators/3/matches"),
                ("delete", "/ioc/indicators/3"),
            ):
                with self.subTest(action=method):
                    response = getattr(self.client, method)(path)
                    self.assertEqual(response.status_code, 404, response.text)

        def test_created_indicator_uses_authenticated_ownership(self):
            self.login(11, 100)
            response = self.client.post("/ioc/indicators", json={
                "indicator_type": "DOMAIN",
                "value": "synthetic.example",
                "severity": "LOW",
                "created_by": 20,
                "client_id": 200,
            })
            self.assertEqual(response.status_code, 201, response.text)
            db = Session()
            try:
                item = db.query(models.IOCIndicator).filter(
                    models.IOCIndicator.value == "synthetic.example"
                ).one()
                self.assertEqual(item.created_by, 11)
                self.assertEqual(item.client_id, 100)
            finally:
                db.close()


        def test_create_valid_indicator_types(self):
            cases = [
                ("IP", "2001:0db8::1", "2001:db8::1"),
                ("DOMAIN", "Synthetic.Example.", "synthetic.example"),
                ("URL", "HTTPS://SYNTHETIC.EXAMPLE:443/a#part",
                 "https://synthetic.example/a"),
                ("MD5", "A" * 32, "a" * 32),
                ("SHA1", "B" * 40, "b" * 40),
                ("SHA256", "B" * 64, "b" * 64),
            ]
            for kind, value, expected in cases:
                with self.subTest(kind=kind):
                    response = self.client.post("/ioc/indicators", json={
                        "indicator_type": kind,
                        "value": value,
                        "severity": "LOW",
                        "confidence": 25,
                        "source": "Isolated regression test",
                        "description": "Synthetic test record",
                    })
                    self.assertEqual(response.status_code, 201, response.text)
                    item = response.json()["indicator"]
                    self.assertEqual(item["value"], expected)
                    self.assertEqual(item["indicator_type"], kind)
                    self.assertEqual(item["severity"], "LOW")
                    self.assertEqual(item["confidence"], 25)
                    self.assertTrue(item["enabled"])

        def test_duplicate_normalized_value_is_rejected(self):
            payload = {
                "indicator_type": "DOMAIN",
                "value": "Duplicate.Example.",
            }
            first = self.client.post("/ioc/indicators", json=payload)
            self.assertEqual(first.status_code, 201, first.text)
            payload["value"] = "duplicate.example"
            second = self.client.post("/ioc/indicators", json=payload)
            self.assertEqual(second.status_code, 409, second.text)
            db = Session()
            try:
                self.assertEqual(
                    db.query(models.IOCIndicator).filter(
                        models.IOCIndicator.value == "duplicate.example",
                        models.IOCIndicator.created_by == 5,
                    ).count(), 1
                )
            finally:
                db.close()

        def test_invalid_values_are_rejected_without_insertion(self):
            cases = [
                ("IP", "999.999.999.999"),
                ("DOMAIN", "https://synthetic.example/path"),
                ("DOMAIN", "localhost"),
                ("URL", "javascript:alert(1)"),
                ("URL", "https://user:password@synthetic.example/"),
                ("MD5", "a" * 31),
                ("SHA1", "g" * 40),
                ("SHA256", "b" * 63),
            ]
            for kind, value in cases:
                with self.subTest(kind=kind, value=value):
                    response = self.client.post("/ioc/indicators", json={
                        "indicator_type": kind, "value": value,
                    })
                    self.assertEqual(response.status_code, 422, response.text)
            db = Session()
            try:
                self.assertEqual(db.query(models.IOCIndicator).count(), 4)
            finally:
                db.close()

        def test_confidence_range_is_enforced(self):
            for confidence in (-1, 101):
                with self.subTest(confidence=confidence):
                    response = self.client.post("/ioc/indicators", json={
                        "indicator_type": "DOMAIN",
                        "value": "confidence.example",
                        "confidence": confidence,
                    })
                    self.assertEqual(response.status_code, 422, response.text)

        def test_invalid_severity_is_rejected(self):
            response = self.client.post("/ioc/indicators", json={
                "indicator_type": "DOMAIN",
                "value": "severity.example",
                "severity": "URGENT",
            })
            self.assertEqual(response.status_code, 422, response.text)

        def test_separate_personal_users_can_register_same_value(self):
            payload = {
                "indicator_type": "DOMAIN",
                "value": "shared-test.example",
            }
            first = self.client.post("/ioc/indicators", json=payload)
            self.assertEqual(first.status_code, 201, first.text)
            self.login(6)
            second = self.client.post("/ioc/indicators", json=payload)
            self.assertEqual(second.status_code, 201, second.text)
            result = self.get_json("/ioc/registry", search="shared-test.example")
            self.assertEqual(result["total"], 1)

        def test_same_client_duplicate_is_rejected(self):
            self.login(10, 100)
            payload = {
                "indicator_type": "DOMAIN",
                "value": "client-duplicate.example",
            }
            first = self.client.post("/ioc/indicators", json=payload)
            self.assertEqual(first.status_code, 201, first.text)
            self.login(11, 100)
            second = self.client.post("/ioc/indicators", json=payload)
            self.assertEqual(second.status_code, 409, second.text)


        def test_disable_and_enable_records_audit(self):
            import json

            response = self.client.patch(
                "/ioc/indicators/1/enabled", json={"enabled": False}
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()["changed"])
            self.assertFalse(response.json()["indicator"]["enabled"])

            summary = self.get_json("/ioc/registry-summary")
            self.assertEqual(summary["enabled"], 1)
            self.assertEqual(summary["disabled"], 1)

            response = self.client.get("/ioc/indicators/1/matches")
            self.assertEqual(response.status_code, 404, response.text)

            response = self.client.patch(
                "/ioc/indicators/1/enabled", json={"enabled": True}
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertTrue(response.json()["indicator"]["enabled"])

            db = Session()
            try:
                rows = db.query(models.AuditLog).order_by(
                    models.AuditLog.id.asc()
                ).all()
                self.assertEqual(len(rows), 2)
                self.assertEqual(
                    [row.action for row in rows],
                    ["IOC_DISABLED", "IOC_ENABLED"],
                )
                for row in rows:
                    self.assertEqual(row.user_id, 5)
                    self.assertEqual(row.username, "user-5")
                    self.assertEqual(json.loads(row.details)["indicator_id"], 1)
                self.assertEqual(
                    json.loads(rows[0].details)["previous_enabled"], True
                )
                self.assertEqual(json.loads(rows[0].details)["enabled"], False)
            finally:
                db.close()

        def test_unchanged_status_creates_no_audit(self):
            response = self.client.patch(
                "/ioc/indicators/1/enabled", json={"enabled": True}
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertFalse(response.json()["changed"])
            db = Session()
            try:
                self.assertEqual(db.query(models.AuditLog).count(), 0)
            finally:
                db.close()

        def test_other_user_cannot_toggle_indicator(self):
            self.login(6)
            response = self.client.patch(
                "/ioc/indicators/1/enabled", json={"enabled": False}
            )
            self.assertEqual(response.status_code, 404, response.text)
            db = Session()
            try:
                self.assertTrue(db.get(models.IOCIndicator, 1).enabled)
                self.assertEqual(db.query(models.AuditLog).count(), 0)
            finally:
                db.close()

        def test_other_client_cannot_toggle_indicator(self):
            self.login(20, 200)
            response = self.client.patch(
                "/ioc/indicators/3/enabled", json={"enabled": False}
            )
            self.assertEqual(response.status_code, 404, response.text)

        def test_same_client_toggle_records_actual_actor(self):
            self.login(11, 100)
            response = self.client.patch(
                "/ioc/indicators/3/enabled", json={"enabled": False}
            )
            self.assertEqual(response.status_code, 200, response.text)
            db = Session()
            try:
                row = db.query(models.AuditLog).one()
                self.assertEqual(row.user_id, 11)
                self.assertEqual(row.username, "user-11")
            finally:
                db.close()

        def test_status_requires_boolean(self):
            for value in ("false", "true", 0, 1, None):
                with self.subTest(value=value):
                    response = self.client.patch(
                        "/ioc/indicators/1/enabled", json={"enabled": value}
                    )
                    self.assertEqual(response.status_code, 422, response.text)

        def test_audit_failure_rolls_back_status(self):
            from unittest.mock import patch
            from sqlalchemy import event

            def fail_audit(*args):
                raise RuntimeError("Synthetic audit failure")

            event.listen(models.AuditLog, "before_insert", fail_audit)
            try:
                # Return a 500 response instead of raising the server exception.
                with TestClient(app, raise_server_exceptions=False) as client:
                    response = client.patch(
                        "/ioc/indicators/1/enabled", json={"enabled": False}
                    )
                    self.assertEqual(response.status_code, 500)
            finally:
                event.remove(models.AuditLog, "before_insert", fail_audit)

            db = Session()
            try:
                self.assertTrue(db.get(models.IOCIndicator, 1).enabled)
                self.assertEqual(db.query(models.AuditLog).count(), 0)
            finally:
                db.close()

        def test_wrong_role_denied(self):
            self.login(5, role=3)
            response = self.client.get("/ioc/registry-summary")
            self.assertEqual(response.status_code, 403, response.text)

    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(IOCAuthorizationTests)
    )
    engine.dispose()
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
