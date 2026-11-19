"""Verify user log endpoints cannot expose unscoped infrastructure logs."""
import os
import sys
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite://"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
import logs
import rbac


class LogScopeTests(unittest.TestCase):
    def setUp(self):
        self.user = SimpleNamespace(
            id=5, role_id=1, client_id=None, username="test-owner"
        )
        self.db = MagicMock()
        self.assessment = SimpleNamespace(
            id=500,
            target="https://authorized.example",
            vapt_status="completed",
            qa_status="not_started",
            monitoring_status="active",
            overall_status="active",
        )

        app = FastAPI()
        app.include_router(logs.router)

        def test_db():
            yield self.db

        app.dependency_overrides[logs.get_db] = test_db
        app.dependency_overrides[rbac.get_current_user] = lambda: self.user
        self.client = TestClient(app)

        self.lookup_patch = patch.object(
            logs, "find_user_assessment", return_value=self.assessment
        )
        self.lookup = self.lookup_patch.start()
        self.journal_patch = patch.object(
            logs, "read_journal",
            side_effect=AssertionError("Shared journal must not be read"),
        )
        self.access_patch = patch.object(
            logs, "read_access_logs",
            side_effect=AssertionError("Shared access log must not be read"),
        )
        self.journal = self.journal_patch.start()
        self.access = self.access_patch.start()

    def tearDown(self):
        self.access_patch.stop()
        self.journal_patch.stop()
        self.lookup_patch.stop()
        self.client.close()

    def test_no_target_cannot_expose_shared_logs(self):
        for kind in ("syslog", "auth", "access"):
            response = self.client.get(f"/logs/{kind}")
            self.assertEqual(response.status_code, 503, response.text)
        self.journal.assert_not_called()
        self.access.assert_not_called()

    def test_owned_target_does_not_authorize_host_logs(self):
        for kind in ("syslog", "auth", "access"):
            response = self.client.get(
                f"/logs/{kind}",
                params={"target": self.assessment.target},
            )
            self.assertEqual(response.status_code, 503, response.text)
        self.journal.assert_not_called()
        self.access.assert_not_called()

    def test_foreign_target_is_denied(self):
        self.lookup.return_value = None
        for kind in ("syslog", "auth", "access"):
            response = self.client.get(
                f"/logs/{kind}", params={"target": "https://foreign.example"}
            )
            self.assertEqual(response.status_code, 404, response.text)

    def test_start_does_not_claim_collection_or_modify_status(self):
        response = self.client.post(
            "/logs/monitoring/start",
            json={"target": self.assessment.target},
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.db.commit.assert_not_called()
        self.assertEqual(self.assessment.overall_status, "active")

    def test_status_does_not_report_legacy_active_as_collection(self):
        response = self.client.get(
            "/logs/monitoring/status",
            params={"target": self.assessment.target},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["monitoring_status"], "unavailable")
        self.assertEqual(body["stored_monitoring_status"], "active")
        self.assertFalse(body["collection_available"])
        self.assertEqual(body["log_sources"], [])

    def test_foreign_monitoring_controls_are_denied(self):
        self.lookup.return_value = None
        for action in ("start", "stop"):
            response = self.client.post(
                f"/logs/monitoring/{action}",
                json={"target": "https://foreign.example"},
            )
            self.assertEqual(response.status_code, 404, response.text)
        response = self.client.get(
            "/logs/monitoring/status",
            params={"target": "https://foreign.example"},
        )
        self.assertEqual(response.status_code, 404, response.text)
        self.db.commit.assert_not_called()

    def test_stop_can_clear_legacy_monitoring_state(self):
        response = self.client.post(
            "/logs/monitoring/stop",
            json={"target": self.assessment.target},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.assessment.monitoring_status, "not_started")
        self.db.commit.assert_called_once()

    def test_incomplete_assessment_cannot_start(self):
        self.assessment.vapt_status = "running"
        response = self.client.post(
            "/logs/monitoring/start",
            json={"target": self.assessment.target},
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.db.commit.assert_not_called()

    def test_unknown_log_type_is_rejected(self):
        self.assertEqual(self.client.get("/logs/unknown").status_code, 404)

    def test_wrong_role_is_denied(self):
        self.user.role_id = 3
        for kind in ("syslog", "auth", "access"):
            self.assertEqual(
                self.client.get(f"/logs/{kind}").status_code, 403
            )
        for action in ("start", "stop"):
            response = self.client.post(
                f"/logs/monitoring/{action}",
                json={"target": self.assessment.target},
            )
            self.assertEqual(response.status_code, 403)
        self.assertEqual(
            self.client.get(
                "/logs/monitoring/status",
                params={"target": self.assessment.target},
            ).status_code,
            403,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
