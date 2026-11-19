"""Isolated network correlation regression tests."""
import copy
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import siem_correlation_engine as engine


class NetworkCorrelationTests(unittest.TestCase):
    def setUp(self):
        rule = copy.deepcopy(next(
            item for item in engine.SIEM_RULES
            if item["id"] == "NET-001"
        ))
        rule.update(
            threshold=10, unique_threshold=10,
            window_seconds=30, response=None,
        )
        for name, value in (
            ("SIEM_RULES", [rule]),
            ("RECENT_EVENTS", []),
            ("RECENT_ALERTS", {}),
            ("ALERT_COOLDOWN_SECONDS", 60),
        ):
            self.enterContext(patch.object(engine, name, value))
        self.block = self.enterContext(patch.object(engine, "block_ip"))
        self.base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def send(self, port, seconds=0, scope="user:5"):
        return engine.evaluate_event({
            "timestamp": (
                self.base + timedelta(seconds=seconds)
            ).isoformat(),
            "event_type": "network_connection_attempt",
            "source": "synthetic-test",
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "destination_port": str(port),
            "_tenant_scope_key": scope,
        }, allow_response_actions=False)

    def burst(self, scope="user:5", seconds=0, first_port=45000):
        results = []
        for port in range(first_port, first_port + 10):
            results.extend(self.send(port, seconds, scope))
        return results

    def tearDown(self):
        self.block.assert_not_called()

    def test_ten_distinct_ports_trigger(self):
        result = self.burst()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["event_count"], 10)

    def test_repeated_port_does_not_trigger(self):
        for _ in range(20):
            self.assertEqual(self.send(45000), [])

    def test_users_do_not_combine_evidence(self):
        for port in range(45000, 45005):
            self.assertEqual(self.send(port, scope="user:5"), [])
        for port in range(45005, 45010):
            self.assertEqual(self.send(port, scope="user:6"), [])
        results = []
        for port in range(45005, 45010):
            results.extend(self.send(port, scope="user:5"))
        self.assertEqual(len(results), 1)
        self.assertEqual(
            {item["_tenant_scope_key"] for item in results[0]["evidence"]},
            {"user:5"},
        )

    def test_cooldown_is_separate_per_user(self):
        self.assertEqual(len(self.burst("user:5")), 1)
        self.assertEqual(len(self.burst("user:6")), 1)

    def test_duplicate_alert_suppressed_within_cooldown(self):
        self.assertEqual(len(self.burst()), 1)
        self.assertEqual(self.send(46000, seconds=1), [])

    def test_new_burst_after_cooldown_triggers(self):
        self.assertEqual(len(self.burst()), 1)
        self.assertEqual(
            len(self.burst(seconds=61, first_port=46000)), 1
        )

    def test_expired_events_do_not_complete_threshold(self):
        for port in range(45000, 45009):
            self.assertEqual(self.send(port), [])
        self.assertEqual(self.send(45009, seconds=31), [])

    def test_future_events_are_excluded(self):
        for port in range(45000, 45009):
            self.assertEqual(self.send(port, seconds=20), [])
        self.assertEqual(self.send(45009, seconds=0), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
