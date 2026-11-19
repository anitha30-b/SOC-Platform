import unittest
from unittest.mock import Mock, patch

import telemetry_detection


class TelemetrySIEMTests(unittest.TestCase):

    def setUp(self):
        self.event = {
            "event_id": "telemetry-test-001",
            "timestamp": "2026-11-12T10:00:00",
            "source": "telemetry:linux",
            "event_type": "authentication_failure",
            "severity": "HIGH",
            "message": "Test authentication failure",
            "target": "test-host",
            "client_id": None,
            "owner_user_id": 5,
            "telemetry_source_id": 24,
            "endpoint_asset_id": 100,
            "_tenant_scope_key": "user:5",
        }

    @patch("telemetry_detection.notify_security_event")
    @patch("telemetry_detection.notify_client_security_event")
    @patch("telemetry_detection.store_security_event")
    @patch("telemetry_detection.map_security_event")
    @patch("telemetry_detection.SessionLocal")
    def test_detection_commit_precedes_notifications(
        self, session_mock, map_mock, store_mock,
        client_notify, siem_notify
    ):
        db = Mock()
        session_mock.return_value = db
        db.query.return_value.filter.return_value.first.return_value = None

        order = []
        store_mock.side_effect = lambda *a, **k: order.append("store")
        db.commit.side_effect = lambda: order.append("commit")
        client_notify.side_effect = lambda *a, **k: order.append("client_notify")
        siem_notify.side_effect = lambda *a, **k: order.append("siem_notify")

        result = telemetry_detection._persist_detection(self.event)

        self.assertTrue(result)
        self.assertEqual(
            order,
            ["store", "commit", "client_notify", "siem_notify"]
        )
        db.close.assert_called_once()

    @patch("telemetry_detection.notify_security_event")
    @patch("telemetry_detection.notify_client_security_event")
    @patch("telemetry_detection.store_security_event")
    @patch("telemetry_detection.SessionLocal")
    def test_duplicate_detection_sends_no_notifications(
        self, session_mock, store_mock, client_notify, siem_notify
    ):
        db = Mock()
        session_mock.return_value = db
        db.query.return_value.filter.return_value.first.return_value = (1,)

        result = telemetry_detection._persist_detection(self.event)

        self.assertFalse(result)
        store_mock.assert_not_called()
        client_notify.assert_not_called()
        siem_notify.assert_not_called()
        db.commit.assert_not_called()
        db.close.assert_called_once()

    @patch("telemetry_detection.notify_security_event")
    @patch("telemetry_detection.notify_client_security_event")
    @patch("telemetry_detection.store_security_event")
    @patch("telemetry_detection.SessionLocal")
    def test_notification_failure_does_not_undo_detection(
        self, session_mock, store_mock, client_notify, siem_notify
    ):
        db = Mock()
        session_mock.return_value = db
        db.query.return_value.filter.return_value.first.return_value = None
        client_notify.side_effect = RuntimeError("Client notification failed")
        siem_notify.side_effect = RuntimeError("SIEM notification failed")

        result = telemetry_detection._persist_detection(self.event)

        self.assertTrue(result)
        db.commit.assert_called_once()
        db.rollback.assert_not_called()
        db.close.assert_called_once()

    @patch("telemetry_detection._persist_detection")
    @patch("telemetry_detection.evaluate_event")
    @patch("telemetry_detection.evaluate_sigma_event")
    def test_generated_detections_preserve_tenant_ownership(
        self, sigma_mock, siem_mock, persist_mock
    ):
        sigma_mock.return_value = [{
            "rule": {
                "id": "TEST-SIGMA-001",
                "title": "Test Sigma rule",
                "level": "high",
                "detection": {"condition": "selection"},
                "logsource": {"product": "linux"},
                "tags": [],
            },
            "filename": "test.yml",
            "matched_selectors": ["selection"],
            "evidence": "Test evidence",
        }]

        siem_mock.return_value = [{
            "rule_id": "TEST-SIEM-001",
            "rule_name": "Test correlation rule",
            "severity": "HIGH",
            "event_count": 3,
            "group_value": "test-host",
            "evidence": [{"event_id": "evidence-001"}],
            "threshold": 3,
            "window_seconds": 300,
            "group_by": "target",
        }]

        persist_mock.return_value = True

        counts = telemetry_detection.process_ingested_telemetry(self.event)

        self.assertEqual(counts, {"sigma": 1, "siem": 1})
        self.assertEqual(persist_mock.call_count, 2)

        for call in persist_mock.call_args_list:
            detection = call.args[0]
            self.assertEqual(detection["owner_user_id"], 5)
            self.assertEqual(detection["telemetry_source_id"], 24)
            self.assertEqual(detection["endpoint_asset_id"], 100)
            self.assertEqual(detection["_tenant_scope_key"], "user:5")
            self.assertEqual(detection["client_id"], None)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TelemetryIngestionTests(unittest.TestCase):

    @patch("telemetry_router.process_ingested_telemetry")
    @patch("telemetry_router.notify_security_event")
    @patch("telemetry_router.notify_client_security_event")
    @patch("telemetry_router.store_security_event")
    @patch("telemetry_router._hash_token", return_value="test-hash")
    def test_ingestion_commits_before_notifications(
        self, hash_mock, store_mock, client_notify,
        siem_notify, detection_mock
    ):
        from types import SimpleNamespace
        from telemetry_router import (
            TelemetryBatchInput,
            TelemetryEventInput,
            ingest_telemetry,
        )
        from models import SecurityEvent, TelemetrySource

        source = SimpleNamespace(
            id=24,
            client_id=None,
            owner_user_id=5,
            enabled=True,
            last_seen_at=None,
        )

        source_query = Mock()
        source_query.filter.return_value.first.return_value = source

        event_query = Mock()
        event_query.filter.return_value.first.return_value = None

        db = Mock()
        db.query.side_effect = [source_query, event_query]

        order = []
        store_mock.side_effect = lambda *a, **k: order.append("store")
        db.commit.side_effect = lambda: order.append("commit")
        client_notify.side_effect = lambda *a, **k: order.append("client_notify")
        siem_notify.side_effect = lambda *a, **k: order.append("siem_notify")
        detection_mock.side_effect = lambda *a, **k: order.append("detection")

        payload = TelemetryBatchInput(events=[
            TelemetryEventInput(
                event_id="isolated-test-event",
                event_type="authentication_failure",
                severity="HIGH",
                message="Isolated SIEM ingestion test",
                target="test-host",
            )
        ])

        result = ingest_telemetry(
            payload,
            x_api_key="isolated-test-key",
            db=db,
        )

        self.assertEqual(result["accepted"], 1)
        self.assertEqual(result["duplicates"], 0)
        self.assertEqual(result["source_id"], 24)

        stored_event = store_mock.call_args.args[1]
        self.assertEqual(stored_event["owner_user_id"], 5)
        self.assertEqual(stored_event["telemetry_source_id"], 24)
        self.assertEqual(stored_event["_tenant_scope_key"], "user:5")

        self.assertEqual(
            order,
            ["store", "commit", "client_notify", "siem_notify", "detection"]
        )
        db.rollback.assert_not_called()
