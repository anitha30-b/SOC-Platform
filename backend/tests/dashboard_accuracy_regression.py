"""Personal dashboard metric tests using actual routes and models."""
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
    import client_portal

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(client_portal.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[client_portal.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    tables = [
        models.Client.__table__,
        models.User.__table__,
        models.Assessment.__table__,
        models.SecurityFinding.__table__,
        models.VAPTReportRun.__table__,
        models.Report.__table__,
    ]
    for table in tables:
        table.create(engine, checkfirst=True)

    def insert_fixture(connection, table, **values):
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
                value = f"test-{column.name}-{marker}"
                length = getattr(column.type, "length", None)
                values[column.name] = value[:length] if length else value
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

    class DashboardTests(unittest.TestCase):
        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid,
                client_id=client,
                role_id=role,
                username=f"user-{uid}",
                email=f"user-{uid}@example.test",
            )

        def setUp(self):
            with engine.begin() as connection:
                for table in reversed(tables):
                    connection.execute(table.delete())

                for client_id in (100, 200):
                    insert_fixture(
                        connection, models.Client.__table__,
                        id=client_id,
                        name=f"Client {client_id}",
                        organization=f"Organization {client_id}",
                    )

                for uid, client in (
                    (5, None), (6, None), (10, 100),
                    (11, 100), (20, 200),
                ):
                    insert_fixture(
                        connection, models.User.__table__,
                        id=uid, username=f"user-{uid}",
                        email=f"user-{uid}@example.test",
                        client_id=client, role_id=1,
                    )

                # Six assessment records, including failed and not-started.
                for index, status in enumerate(
                    ("completed", "running", "failed", "queued",
                     "not_started", "cancelled"),
                    start=1,
                ):
                    insert_fixture(
                        connection, models.Assessment.__table__,
                        id=500 + index, user_id=5,
                        target=f"https://owner-{index}.example",
                        vapt_status=status,
                    )

                for index in range(1, 4):
                    insert_fixture(
                        connection, models.SecurityFinding.__table__,
                        id=500 + index,
                        finding_id=f"OWNER-F-{index}",
                        user_id=5, assessment_id=501,
                        title=f"Owner finding {index}",
                        severity="MEDIUM",
                    )

                for index, status in enumerate(
                    ("COMPLETED", "COMPLETED", "RUNNING", "FAILED", "QUEUED"),
                    start=1,
                ):
                    insert_fixture(
                        connection, models.VAPTReportRun.__table__,
                        id=500 + index,
                        report_run_id=f"OWNER-REPORT-{index}",
                        job_id=f"OWNER-JOB-{index}",
                        user_id=5, assessment_id=501,
                        status=status, report_type="COMPLETE",
                        canonical_data='{"findings":[]}',
                    )

                # Other accounts must not contribute to personal metrics.
                for uid in (6, 10, 11, 20):
                    insert_fixture(
                        connection, models.Assessment.__table__,
                        id=uid * 1000, user_id=uid,
                        target=f"https://peer-{uid}.example",
                        vapt_status="completed",
                    )
                    insert_fixture(
                        connection, models.SecurityFinding.__table__,
                        id=uid * 1000,
                        finding_id=f"PEER-F-{uid}",
                        user_id=uid, assessment_id=uid * 1000,
                        title=f"Peer finding {uid}", severity="HIGH",
                    )
                    insert_fixture(
                        connection, models.VAPTReportRun.__table__,
                        id=uid * 1000,
                        report_run_id=f"PEER-REPORT-{uid}",
                        job_id=f"PEER-JOB-{uid}",
                        user_id=uid, assessment_id=uid * 1000,
                        status="COMPLETED", report_type="COMPLETE",
                    )

                # Legacy generated reports must not inflate VAPT report count.
                insert_fixture(
                    connection, models.Report.__table__,
                    id=500, user_id=5, assessment_id=501,
                    report_id="LEGACY-REPORT",
                    report_type="COMPLETE", status="GENERATED",
                )

            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def overview(self):
            response = self.client.get("/client/dashboard")
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        def test_counts_all_owned_assessments_not_only_successful_scans(self):
            body = self.overview()
            self.assertEqual(body["total_assessments"], 6)
            self.assertEqual(body["total_scans"], 6)

        def test_findings_count_is_personal(self):
            body = self.overview()
            self.assertEqual(body["total_findings"], 3)
            self.assertEqual(body["total_vulnerabilities"], 3)

        def test_only_completed_vapt_reports_are_counted(self):
            body = self.overview()
            self.assertEqual(body["total_reports"], 2)
            self.assertEqual(
                body["report_metric"], "completed_vapt_report_runs"
            )

        def test_legacy_reports_do_not_affect_vapt_count(self):
            with engine.begin() as connection:
                insert_fixture(
                    connection, models.Report.__table__,
                    id=501, user_id=5, assessment_id=501,
                    report_id="SECOND-LEGACY",
                    report_type="COMPLETE", status="READY",
                )
            self.assertEqual(self.overview()["total_reports"], 2)

        def test_same_client_does_not_expand_personal_metrics(self):
            for uid in (10, 11):
                with self.subTest(uid=uid):
                    self.login(uid, 100)
                    body = self.overview()
                    self.assertEqual(body["metrics_scope"], "personal")
                    self.assertEqual(body["total_assessments"], 1)
                    self.assertEqual(body["total_findings"], 1)
                    self.assertEqual(body["total_reports"], 1)

        def test_other_client_counts_are_isolated(self):
            self.login(20, 200)
            body = self.overview()
            self.assertEqual(body["total_assessments"], 1)
            self.assertEqual(body["total_findings"], 1)
            self.assertEqual(body["total_reports"], 1)

        def test_client_metadata_is_preserved(self):
            self.login(10, 100)
            body = self.overview()
            self.assertEqual(body["client_id"], 100)
            self.assertEqual(body["client_name"], "Client 100")
            self.assertEqual(body["organization"], "Organization 100")
            self.assertEqual(body["client"]["id"], 100)

        def test_empty_account_returns_zero_not_other_users_totals(self):
            self.login(99)
            body = self.overview()
            self.assertEqual(body["total_assessments"], 0)
            self.assertEqual(body["total_findings"], 0)
            self.assertEqual(body["total_reports"], 0)
            self.assertIsNone(body["client"])

        def test_wrong_role_is_denied(self):
            self.login(role=3)
            response = self.client.get("/client/dashboard")
            self.assertEqual(response.status_code, 403, response.text)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DashboardTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
