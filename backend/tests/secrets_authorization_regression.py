"""Isolated Secrets registry tests. No production database or scans."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import json
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
    import code_security_router
    import rbac
    from secrets_metadata import secret_metadata

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(code_security_router.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[database.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    class SecretsTests(unittest.TestCase):
        marker = "SYNTHETIC_SECRET_MUST_NOT_APPEAR_728491"

        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, username=f"user-{uid}",
                role_id=role, client_id=client,
            )

        def setUp(self):
            models.User.__table__.create(engine, checkfirst=True)
            models.SecurityFinding.__table__.create(engine, checkfirst=True)

            with engine.begin() as connection:
                connection.execute(text(
                    "CREATE TABLE IF NOT EXISTS assessments "
                    "(id INTEGER PRIMARY KEY, user_id INTEGER)"
                ))
                for name in ("security_findings", "assessments", "users"):
                    connection.execute(text(f"DELETE FROM {name}"))

            now = datetime.now(timezone.utc).replace(tzinfo=None)
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
                    db.execute(text(
                        "INSERT INTO assessments (id, user_id) VALUES (:id, :uid)"
                    ), {"id": uid, "uid": uid})

                for fid, owner, rule, tool in (
                    (1, 5, "generic-api-key", "Gitleaks"),
                    (2, 5, "jwt", "Gitleaks"),
                    (3, 5, "private-key", "Gitleaks"),
                    (4, 5, "custom-unknown-rule", "Gitleaks"),
                    (5, 6, "generic-api-key", "Gitleaks"),
                    (6, 10, "jwt", "Gitleaks"),
                    (7, 11, "private-key", "Gitleaks"),
                    (8, 20, "jwt", "Gitleaks"),
                    (9, 5, "generic-api-key", "Semgrep"),
                ):
                    db.add(models.SecurityFinding(
                        id=fid,
                        finding_id=f"SYNTHETIC-FIND-{fid}",
                        user_id=owner,
                        assessment_id=owner,
                        tool_name=tool,
                        tool_category="Code Security",
                        title=self.marker,
                        description=self.marker,
                        vulnerability="Synthetic finding",
                        severity="HIGH",
                        risk_level="LEVEL_1",
                        status="OPEN",
                        evidence=json.dumps({
                            "file_path": f"synthetic/file-{fid}.py",
                            "line_start": 10,
                            "line_end": 10,
                            "rule_id": rule,
                            "Secret": self.marker,
                            "Match": self.marker,
                            "code_snippet": self.marker,
                            "description": self.marker,
                            "nested": {"secret": self.marker},
                        }),
                        request_data=self.marker,
                        response_data=self.marker,
                        detected_at=now,
                        created_at=now,
                        updated_at=now,
                    ))
                db.commit()

            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def fetch(self, **params):
            response = self.client.get(
                "/code-security/secrets-registry", params=params
            )
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        def test_personal_registry_excludes_other_users_and_tools(self):
            data = self.fetch()
            self.assertEqual(data["total"], 4)
            self.assertEqual(
                [row["id"] for row in data["findings"]], [4, 3, 2, 1]
            )

        def test_other_personal_user_only_sees_own_finding(self):
            self.login(6)
            data = self.fetch()
            self.assertEqual(data["total"], 1)
            self.assertEqual([row["id"] for row in data["findings"]], [5])

        def test_same_client_does_not_share_personal_findings(self):
            self.login(11, 100)
            data = self.fetch()
            self.assertEqual(data["scope"], "personal")
            self.assertEqual(data["total"], 1)
            self.assertEqual([row["id"] for row in data["findings"]], [7])

        def test_other_client_only_sees_own_finding(self):
            self.login(20, 200)
            data = self.fetch()
            self.assertEqual(data["total"], 1)
            self.assertEqual([row["id"] for row in data["findings"]], [8])

        def test_wrong_role_is_denied(self):
            self.login(role=3)
            response = self.client.get("/code-security/secrets-registry")
            self.assertEqual(response.status_code, 403, response.text)

        def test_response_excludes_raw_secret_fields(self):
            data = self.fetch()
            encoded = json.dumps(data)
            self.assertNotIn(self.marker, encoded)
            expected_fields = {
                "id", "assessment_id", "tool", "rule_id", "category",
                "severity", "status", "file_path", "line_start",
                "line_end", "secret_value_included", "remediation_guidance",
            }
            for row in data["findings"]:
                self.assertEqual(set(row), expected_fields)
                self.assertFalse(row["secret_value_included"])

        def test_search_does_not_search_secret_values(self):
            data = self.fetch(search=self.marker)
            self.assertEqual(data["matched_total"], 0)
            self.assertEqual(data["findings"], [])

        def test_categories_and_unknown_rule(self):
            expected = {
                "api_keys": 1,
                "tokens": 2,
                "credentials": 3,
                "unclassified": 4,
            }
            for category, fid in expected.items():
                with self.subTest(category=category):
                    data = self.fetch(category=category)
                    self.assertEqual(data["matched_total"], 1)
                    self.assertEqual(
                        [row["id"] for row in data["findings"]], [fid]
                    )
                    self.assertEqual(data["total"], 4)
            self.assertEqual(self.fetch()["by_category"], {
                key: 1 for key in expected
            })

        def test_pagination_and_search_apply_before_page(self):
            data = self.fetch(page_size=2)
            self.assertEqual([row["id"] for row in data["findings"]], [4, 3])
            self.assertEqual(data["next_offset"], 2)
            data = self.fetch(page_size=2, offset=2)
            self.assertEqual([row["id"] for row in data["findings"]], [2, 1])
            self.assertIsNone(data["next_offset"])
            data = self.fetch(search="file-1.py", page_size=1)
            self.assertEqual(data["matched_total"], 1)
            self.assertEqual([row["id"] for row in data["findings"]], [1])

        def test_invalid_parameters_are_rejected(self):
            for params in (
                {"category": "unsupported"},
                {"offset": -1},
                {"page_size": 0},
                {"page_size": 101},
                {"search": "x" * 201},
            ):
                with self.subTest(params=params):
                    response = self.client.get(
                        "/code-security/secrets-registry", params=params
                    )
                    self.assertEqual(response.status_code, 422, response.text)

        def test_malformed_evidence_stays_metadata_only(self):
            with Session() as db:
                db.get(models.SecurityFinding, 1).evidence = "{invalid-json"
                db.commit()
            data = self.fetch()
            row = next(row for row in data["findings"] if row["id"] == 1)
            self.assertEqual(row["category"], "unclassified")
            self.assertIsNone(row["rule_id"])
            self.assertIsNone(row["file_path"])
            self.assertNotIn(self.marker, json.dumps(data))

        def test_projection_rejects_invalid_metadata_types(self):
            item = SimpleNamespace(
                id=1, assessment_id=5, severity=self.marker,
                status=self.marker,
                evidence=json.dumps({
                    "rule_id": "<invalid>",
                    "file_path": ["not", "a", "path"],
                    "line_start": True,
                    "line_end": -2,
                    "Secret": self.marker,
                }),
            )
            row = secret_metadata(item)
            self.assertIsNone(row["rule_id"])
            self.assertIsNone(row["file_path"])
            self.assertIsNone(row["line_start"])
            self.assertIsNone(row["line_end"])
            self.assertEqual(row["severity"], "UNKNOWN")
            self.assertEqual(row["status"], "OTHER")
            self.assertNotIn(self.marker, json.dumps(row))

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecretsTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    engine.dispose()
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
