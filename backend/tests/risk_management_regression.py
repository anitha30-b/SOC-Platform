"""Isolated risk tests using an in-memory database; no scans."""
import os
import sys
from pathlib import Path


def main():
    os.environ["DATABASE_URL"] = "sqlite://"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

    import unittest
    from datetime import datetime, timedelta
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
    import risk_assessment_router

    Session = sessionmaker(bind=engine)
    identity = {}
    app = FastAPI()
    app.include_router(risk_assessment_router.router)

    def test_db():
        with Session() as db:
            yield db

    app.dependency_overrides[database.get_db] = test_db
    app.dependency_overrides[rbac.get_current_user] = lambda: identity["user"]

    class RiskTests(unittest.TestCase):
        marker = "SYNTHETIC_RAW_EVIDENCE_DO_NOT_RETURN_4926"

        def login(self, uid=5, client=None, role=1):
            identity["user"] = SimpleNamespace(
                id=uid, role_id=role, client_id=client,
                username=f"user-{uid}",
            )

        def setUp(self):
            for model in (
                models.User, models.Assessment,
                models.SecurityFinding, models.RiskAssessmentRun,
            ):
                model.__table__.create(engine, checkfirst=True)
            with engine.begin() as connection:
                for table in (
                    "risk_assessment_runs", "security_findings", "assessments", "users"
                ):
                    connection.execute(text(f"DELETE FROM {table}"))

            now = datetime.utcnow()
            with Session() as db:
                for uid, client in ((5, None), (6, None), (10, 100), (11, 100), (20, 200)):
                    db.add(models.User(
                        id=uid, username=f"user-{uid}", email=f"{uid}@example.invalid",
                        hashed_password="synthetic-unused", role_id=1, client_id=client,
                    ))
                for fid in range(1, 31):
                    db.add(models.SecurityFinding(
                        id=fid, finding_id=f"OWN-{fid}", user_id=5,
                        assessment_id=999, tool_name="Synthetic",
                        title=f"Synthetic finding {fid}", vulnerability="Test issue",
                        affected_asset="asset-a", severity="HIGH", risk_level="LEVEL_1",
                        status="OPEN", cvss_score=7.5,
                        evidence=self.marker, request_data=self.marker,
                        response_data=self.marker, detected_at=now,
                        created_at=now, updated_at=now,
                    ))
                for fid, uid in ((40, 6), (41, 10), (42, 11), (43, 20)):
                    db.add(models.SecurityFinding(
                        id=fid, finding_id=f"OTHER-{uid}", user_id=uid,
                        assessment_id=999, tool_name="Synthetic", title="Other owner",
                        vulnerability="Other issue", affected_asset="other-asset",
                        severity="LOW", risk_level="LEVEL_3", status="OPEN",
                        detected_at=now, created_at=now, updated_at=now,
                    ))
                # A completed run older than more than 20 unfinished runs.
                for index in range(23):
                    completed = index == 0
                    db.add(models.RiskAssessmentRun(
                        id=index + 1, assessment_run_id=f"RUN-{index}",
                        job_id=f"JOB-{index}", user_id=5, assessment_id=999,
                        status="COMPLETED" if completed else "RUNNING",
                        overall_risk="HIGH" if completed else None,
                        total_findings=30 if completed else 0,
                        average_cvss=7.5 if completed else 0,
                        highest_cvss=7.5 if completed else 0,
                        created_at=now + timedelta(seconds=index),
                        completed_at=now if completed else None,
                    ))
                db.add(models.RiskAssessmentRun(
                    id=99, assessment_run_id="OTHER-RUN", job_id="OTHER-JOB",
                    user_id=6, assessment_id=999, status="COMPLETED",
                    overall_risk="LOW", total_findings=1,
                    created_at=now + timedelta(days=1),
                    completed_at=now + timedelta(days=1),
                ))
                db.commit()
            self.login()
            self.client = TestClient(app)

        def tearDown(self):
            self.client.close()

        def fetch(self, **params):
            response = self.client.get(
                "/vapt/risk-assessment/management", params=params
            )
            self.assertEqual(response.status_code, 200, response.text)
            return response.json()

        def test_personal_findings_exclude_other_owners(self):
            result = self.fetch()
            self.assertEqual(result["total"], 30)
            self.assertTrue(all(row["finding_id"].startswith("OWN-") for row in result["rows"]))

        def test_same_client_findings_are_not_shared(self):
            self.login(11, 100)
            result = self.fetch()
            self.assertEqual(result["scope"], "personal")
            self.assertEqual([row["finding_id"] for row in result["rows"]], ["OTHER-11"])

        def test_other_client_only_sees_own_findings(self):
            self.login(20, 200)
            self.assertEqual(self.fetch()["total"], 1)

        def test_search_and_pagination(self):
            self.assertEqual(len(self.fetch()["rows"]), 25)
            self.assertEqual(len(self.fetch(offset=25)["rows"]), 5)
            result = self.fetch(search="OWN-1", page_size=2)
            self.assertEqual(result["matched_total"], 11)
            self.assertEqual(len(result["rows"]), 2)
            self.assertEqual(result["next_offset"], 2)

        def test_groups_cover_all_findings(self):
            for view in ("assets", "vulnerabilities"):
                result = self.fetch(view=view)
                self.assertEqual(result["total"], 1)
                self.assertEqual(result["rows"][0]["findings"], 30)
                self.assertEqual(result["rows"][0]["high_critical"], 30)

        def test_metadata_excludes_raw_evidence(self):
            result = self.client.get("/vapt/risk-assessment/management")
            self.assertNotIn(self.marker, result.text)
            for forbidden in ("evidence", "request_data", "response_data"):
                self.assertNotIn(forbidden, result.json()["rows"][0])

        def test_run_history_excludes_other_owner_and_unfinished_measurements(self):
            result = self.fetch(view="trends")
            self.assertEqual(result["total"], 23)
            unfinished = next(row for row in result["rows"] if row["status"] == "RUNNING")
            self.assertIsNone(unfinished["total_findings"])
            self.assertIsNone(unfinished["highest_cvss"])

        def test_completed_run_lookup_is_not_limited_to_recent_twenty(self):
            response = self.client.get("/vapt/risk-assessment/overview")
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            self.assertEqual(len(result["recent_risk_assessments"]), 20)
            self.assertEqual(
                result["latest_completed_risk_assessment"]["assessment_run_id"],
                "RUN-0",
            )

        def test_existing_overview_client_scope_is_preserved(self):
            self.login(10, 100)
            response = self.client.get("/vapt/risk-assessment/overview")
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["metrics"]["total_findings"], 2)

        def test_wrong_role_denied(self):
            self.login(role=3)
            response = self.client.get("/vapt/risk-assessment/management")
            self.assertEqual(response.status_code, 403)

        def test_invalid_parameters(self):
            for params in (
                {"view": "invalid"}, {"offset": -1},
                {"page_size": 0}, {"page_size": 101},
                {"search": "x" * 201},
            ):
                response = self.client.get(
                    "/vapt/risk-assessment/management", params=params
                )
                self.assertEqual(response.status_code, 422)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RiskTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
