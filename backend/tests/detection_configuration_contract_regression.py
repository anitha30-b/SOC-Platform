"""Actual admin API -> stored threshold configuration -> engine contract."""
from datetime import datetime
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ.setdefault('JWT_SECRET_KEY', 'isolated-detection-contract-key')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from database import Base, get_db
import models
import rbac
import detection_config_router
import detection_engine


class ConfigurationContractTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite://', poolclass=StaticPool,
                                    connect_args={'check_same_thread': False})
        Base.metadata.create_all(self.engine)
        self.Factory = sessionmaker(bind=self.engine)
        self.identity = SimpleNamespace(id=30, username='admin-fixture', role_id=3, client_id=None)
        app = FastAPI()
        app.include_router(detection_config_router.router)
        def db_dependency():
            with self.Factory() as db:
                yield db
        app.dependency_overrides[get_db] = db_dependency
        app.dependency_overrides[rbac.get_current_user] = lambda: self.identity
        self.client = TestClient(app)
        self.payload = dict(name='fixture-threshold', category='Verification',
            description='Isolated API/engine contract fixture', detection_type='Threshold-Based',
            severity='LOW', enabled=True, threshold=3, time_window_minutes=5,
            source='api-fixture', event_type='AUTH_FAILURE', conditions=None)

    def tearDown(self):
        self.client.close()
        self.engine.dispose()

    def create(self):
        response = self.client.post('/admin/detection-config', json=self.payload)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_creation_preserves_threshold_window_and_filters(self):
        row = self.create()
        for field in ('threshold', 'time_window_minutes', 'source', 'event_type'):
            self.assertEqual(row[field], self.payload[field])
        rows = self.client.get('/admin/detection-config').json()
        self.assertEqual(rows[0]['threshold'], 3)

    def test_partial_update_retains_other_threshold_fields(self):
        row = self.create()
        response = self.client.put(f'/admin/detection-config/{row["id"]}', json={'threshold': 5})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['threshold'], 5)
        self.assertEqual(response.json()['time_window_minutes'], 5)
        self.assertEqual(response.json()['source'], 'api-fixture')

    def test_missing_threshold_configuration_rejected(self):
        for key in ('threshold', 'time_window_minutes'):
            payload = dict(self.payload)
            payload.pop(key)
            response = self.client.post('/admin/detection-config', json=payload)
            self.assertEqual(response.status_code, 422, response.text)

    def test_invalid_threshold_values_rejected(self):
        for value in (0, -1):
            response = self.client.post('/admin/detection-config', json={**self.payload, 'threshold': value})
            self.assertEqual(response.status_code, 422, response.text)

    def test_update_cannot_remove_required_threshold_window(self):
        row = self.create()
        response = self.client.put(f'/admin/detection-config/{row["id"]}', json={'time_window_minutes': None})
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.client.get('/admin/detection-config').json()[0]['time_window_minutes'], 5)

    def test_user_cannot_create_global_admin_rule(self):
        self.identity.role_id = 1
        response = self.client.post('/admin/detection-config', json=self.payload)
        self.assertEqual(response.status_code, 403, response.text)

    def test_api_created_threshold_fires_on_third_event_only(self):
        row = self.create()
        with self.Factory() as db:
            for index in range(1, 4):
                event = models.SecurityEvent(id=index, event_id=f'fixture-{index}',
                    source='api-fixture', event_type='AUTH_FAILURE', timestamp=datetime(2026,1,1),
                    severity='INFO', message='Isolated fixture', owner_user_id=1, alert_status='ACTIVE')
                db.add(event)
                db.flush()
                summary = detection_engine.evaluate_event(db, event)
                self.assertEqual(summary['detections_matched'], int(index == 3))
            self.assertEqual(db.query(models.DetectionResult).filter(
                models.DetectionResult.detection_config_id == row['id']).count(), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
