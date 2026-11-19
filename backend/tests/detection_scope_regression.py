"""Actual detection-engine tests using isolated SQLite fixtures only."""
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ.setdefault('JWT_SECRET_KEY', 'isolated-detection-scope-test-key')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import models
import detection_engine as detection


class DetectionScopeTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite://', poolclass=StaticPool,
                                    connect_args={'check_same_thread': False})
        for model in (models.Role, models.Client, models.User, models.Assessment,
                      models.TelemetrySource, models.SecurityEvent,
                      models.DetectionConfiguration, models.AlertConfiguration,
                      models.DetectionResult, models.AlertResult):
            model.__table__.create(self.engine)
        self.db = sessionmaker(bind=self.engine)()
        self.db.add(models.Role(id=1, name='Client'))
        for cid in (100, 200):
            self.db.add(models.Client(id=cid, name=f'client-{cid}', email=f'client-{cid}@example.invalid'))
        for uid, cid in ((1, None), (2, None), (10, 100), (11, 100), (20, 200)):
            self.db.add(models.User(id=uid, username=f'user-{uid}',
                                    email=f'user-{uid}@example.invalid',
                                    hashed_password='unused-fixture', role_id=1, client_id=cid))
        self.db.flush()
        self.now = datetime(2026, 1, 1, 12, 0, 0)
        self.counter = 0

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def event(self, owner=1, client=None, when=None, kind='LOGIN_FAILURE'):
        self.counter += 1
        row = models.SecurityEvent(
            id=self.counter, event_id=f'fixture-{self.counter}',
            timestamp=when or self.now, source='scope-regression', event_type=kind,
            severity='HIGH', message='Synthetic isolated detection fixture',
            target='test-host', owner_user_id=owner, client_id=client,
            alert_status='ACTIVE',
        )
        self.db.add(row)
        self.db.flush()
        return row

    def correlation_rule(self):
        return SimpleNamespace(id=1, conditions=json.dumps({'correlation': {
            'first': {'field': 'event_type', 'operator': 'equals', 'value': 'LOGIN_FAILURE'},
            'then': {'field': 'event_type', 'operator': 'equals', 'value': 'LOGIN_SUCCESS'},
            'time_window_minutes': 10, 'group_by': 'target',
        }}))

    def anomaly_rule(self):
        return SimpleNamespace(id=1, conditions=json.dumps({'anomaly': {
            'baseline_window_minutes': 60, 'detection_window_minutes': 5,
            'multiplier': 3, 'minimum_events': 5, 'group_by': 'source',
        }}))

    def test_threshold_separates_personal_accounts(self):
        self.event(owner=2)
        self.event(owner=2)
        current = self.event(owner=1)
        self.assertFalse(detection.threshold_reached(self.db, current, 3, 5))

    def test_threshold_separates_clients(self):
        self.event(owner=10, client=100)
        self.event(owner=11, client=100)
        current = self.event(owner=20, client=200)
        self.assertFalse(detection.threshold_reached(self.db, current, 3, 5))

    def test_threshold_shares_within_one_client(self):
        self.event(owner=10, client=100)
        self.event(owner=11, client=100)
        current = self.event(owner=10, client=100)
        self.assertTrue(detection.threshold_reached(self.db, current, 3, 5))

    def test_threshold_fires_at_boundary_for_same_owner(self):
        self.event()
        second = self.event()
        self.assertFalse(detection.threshold_reached(self.db, second, 3, 5))
        third = self.event()
        self.assertTrue(detection.threshold_reached(self.db, third, 3, 5))

    def test_global_events_do_not_use_tenant_counts(self):
        self.event(owner=1)
        self.event(owner=1)
        current = self.event(owner=None)
        self.assertFalse(detection.threshold_reached(self.db, current, 3, 5))

    def test_global_only_threshold_remains_supported(self):
        self.event(owner=None)
        self.event(owner=None)
        current = self.event(owner=None)
        self.assertTrue(detection.threshold_reached(self.db, current, 3, 5))

    def test_correlation_does_not_join_other_owner(self):
        self.event(owner=2, when=self.now-timedelta(minutes=1))
        current = self.event(owner=1, kind='LOGIN_SUCCESS')
        self.assertFalse(detection.correlation_reached(self.db, current, self.correlation_rule()))

    def test_correlation_matches_same_owner(self):
        self.event(owner=1, when=self.now-timedelta(minutes=1))
        current = self.event(owner=1, kind='LOGIN_SUCCESS')
        self.assertTrue(detection.correlation_reached(self.db, current, self.correlation_rule()))

    def test_anomaly_does_not_count_other_owner_burst(self):
        for _ in range(4):
            self.event(owner=2)
        current = self.event(owner=1)
        self.assertFalse(detection.anomaly_reached(self.db, current, self.anomaly_rule()))

    def test_other_owner_baseline_does_not_hide_real_burst(self):
        for _ in range(120):
            self.event(owner=2, when=self.now-timedelta(minutes=20))
        for _ in range(4):
            self.event(owner=1)
        current = self.event(owner=1)
        self.assertTrue(detection.anomaly_reached(self.db, current, self.anomaly_rule()))

    def test_cross_owner_counts_do_not_create_saved_alert(self):
        self.db.add(models.AlertConfiguration(
            name='threshold-alert', category='fixture', description='Isolated fixture',
            severity='HIGH', priority='HIGH', source='scope-regression',
            event_type='LOGIN_FAILURE', threshold=3, time_window_minutes=5, enabled=True,
        ))
        self.db.flush()
        self.event(owner=2)
        self.event(owner=2)
        current = self.event(owner=1)
        summary = detection.evaluate_event(self.db, current)
        self.assertEqual(summary['alerts_generated'], 0)
        self.assertEqual(self.db.query(models.AlertResult).count(), 0)

    def test_matching_results_are_not_duplicated(self):
        condition = json.dumps({'field': 'severity', 'operator': 'equals', 'value': 'HIGH'})
        self.db.add_all([
            models.DetectionConfiguration(name='one-detection', category='fixture',
                description='Isolated fixture', detection_type='Rule-Based',
                severity='HIGH', conditions=condition, enabled=True),
            models.AlertConfiguration(name='one-alert', category='fixture',
                description='Isolated fixture', severity='HIGH', priority='HIGH',
                conditions=condition, enabled=True),
        ])
        self.db.flush()
        current = self.event()
        first = detection.evaluate_event(self.db, current)
        second = detection.evaluate_event(self.db, current)
        self.assertEqual(first, {'detections_matched': 1, 'alerts_generated': 1})
        self.assertEqual(second, {'detections_matched': 0, 'alerts_generated': 0})
        self.assertEqual(self.db.query(models.DetectionResult).count(), 1)
        self.assertEqual(self.db.query(models.AlertResult).count(), 1)

    def test_disabled_rule_does_not_match(self):
        self.db.add(models.DetectionConfiguration(name='disabled', category='fixture',
            description='Isolated fixture', detection_type='Rule-Based', severity='HIGH', enabled=False))
        self.db.flush()
        self.assertEqual(detection.evaluate_event(self.db, self.event())['detections_matched'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
