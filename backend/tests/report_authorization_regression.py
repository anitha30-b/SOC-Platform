"""Isolated report authorization tests; no production DB or report jobs."""
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
    import rbac
    import vapt_reporting_router as reporting

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(reporting.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[database.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    class ReportTests(unittest.TestCase):
        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, username=f"user-{uid}", client_id=client, role_id=role,
            )

        def setUp(self):
            models.VAPTReportRun.__table__.create(engine, checkfirst=True)
            with engine.begin() as connection:
                connection.execute(text("DELETE FROM vapt_report_runs"))

            reporting.REPORT_JOBS.clear()
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            with Session() as db:
                for index, owner, status in (
                    (1, 5, "COMPLETED"),
                    (2, 6, "COMPLETED"),
                    (3, 10, "COMPLETED"),
                    (4, 11, "COMPLETED"),
                    (5, 5, "RUNNING"),
                ):
                    db.add(models.VAPTReportRun(
                        id=index, report_run_id=f"REPORT-{index}",
                        job_id=f"JOB-{index}", user_id=owner,
                        assessment_id=index, status=status, report_type="COMPLETE",
                        formats=json.dumps(["JSON", "XML", "PDF"]),
                        canonical_data=json.dumps({
                            "report_metadata": {"assessment_id": index},
                            "findings": [],
                        }),
                        created_at=now, updated_at=now,
                        completed_at=now if status == "COMPLETED" else None,
                    ))
                db.commit()
            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()
            reporting.REPORT_JOBS.clear()

        def get(self, suffix):
            return self.client.get("/vapt/reporting/" + suffix)

        def test_owned_persisted_results_without_memory_job(self):
            response = self.get("JOB-1/results")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["report_run_id"], "REPORT-1")

        def test_owned_persisted_progress_without_memory_job(self):
            response = self.get("JOB-1/progress")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["status"], "completed")

        def test_owned_json_download_without_memory_job(self):
            response = self.get("JOB-1/download/JSON")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["report_metadata"]["assessment_id"], 1)

        def test_owned_xml_download_without_memory_job(self):
            response = self.get("JOB-1/download/XML")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertIn(b"<VAPTReport>", response.content)

        def test_other_owner_cannot_access_any_report_endpoint(self):
            for suffix in ("progress", "results", "download/JSON"):
                self.assertEqual(self.get(f"JOB-2/{suffix}").status_code, 404)

        def test_same_client_does_not_share_reports(self):
            self.login(10, 100)
            for suffix in ("progress", "results", "download/JSON"):
                self.assertEqual(self.get(f"JOB-4/{suffix}").status_code, 404)

        def test_other_users_memory_job_is_not_accessible(self):
            reporting.REPORT_JOBS["LIVE"] = {
                "user_id": 6, "status": "running",
                "stage": "Other user's stage", "progress": 50,
                "result": {"private": "must not return"},
            }
            for suffix in ("progress", "results", "download/JSON"):
                self.assertEqual(self.get(f"LIVE/{suffix}").status_code, 404)

        def test_owned_memory_job_progress(self):
            reporting.REPORT_JOBS["LIVE"] = {
                "user_id": 5, "status": "running",
                "stage": "Building report", "progress": 60,
            }
            response = self.get("LIVE/progress")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["progress"], 60)

        def test_legacy_memory_job_without_owner_is_denied(self):
            reporting.REPORT_JOBS["LEGACY"] = {
                "status": "completed", "result": {"private": "must not return"},
            }
            self.assertEqual(self.get("LEGACY/progress").status_code, 404)
            self.assertEqual(self.get("LEGACY/results").status_code, 404)

        def test_unfinished_report_cannot_be_downloaded(self):
            self.assertEqual(self.get("JOB-5/results").status_code, 404)
            self.assertEqual(self.get("JOB-5/download/JSON").status_code, 404)

        def test_unsupported_format_rejected(self):
            self.assertEqual(self.get("JOB-1/download/EXE").status_code, 400)


        def test_history_only_lists_personally_owned_reports(self):
            response = self.get("history")
            self.assertEqual(response.status_code, 200, response.text)
            body = response.json()
            self.assertEqual(body["scope"], "personal")
            self.assertEqual(body["total"], 2)
            self.assertEqual(
                {item["report_run_id"] for item in body["reports"]},
                {"REPORT-1", "REPORT-5"},
            )
            self.assertNotIn("canonical_data", body["reports"][0])

        def test_history_same_client_does_not_share_reports(self):
            self.login(10, 100)
            response = self.get("history")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(
                [item["report_run_id"] for item in response.json()["reports"]],
                ["REPORT-3"],
            )

        def test_history_search_before_pagination(self):
            response = self.client.get(
                "/vapt/reporting/history",
                params={"search": "REPORT-1", "page_size": 1},
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["matched_total"], 1)
            self.assertEqual(response.json()["reports"][0]["report_run_id"], "REPORT-1")

        def test_history_invalid_parameters_and_wrong_role(self):
            for params in ({"offset": -1}, {"page_size": 101}, {"search": "x" * 201}):
                response = self.client.get("/vapt/reporting/history", params=params)
                self.assertEqual(response.status_code, 422)
            self.login(role=3)
            self.assertEqual(self.get("history").status_code, 403)

        def test_wrong_role_denied(self):
            self.login(role=3)
            for suffix in ("progress", "results", "download/JSON"):
                self.assertEqual(self.get(f"JOB-1/{suffix}").status_code, 403)

    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ReportTests)
    )
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
