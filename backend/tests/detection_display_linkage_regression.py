"""Actual HTTP serialization tests using only the isolated SQLite fixture."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import admin_user_integration_regression as fixture

models, support = fixture.models, fixture.support
models.DetectionResult.__table__.create(support.engine, checkfirst=True)


class DetectionDisplayTests(unittest.TestCase):
    select_user = fixture.RoleBoundaryTests.select_user

    def setUp(self):
        with support.Factory() as db:
            db.query(models.DetectionResult).delete()
            db.commit()
        fixture.RoleBoundaryTests.setUp(self)
        with support.Factory() as db:
            for ident, event_id, rule_id, name in (
                (1, 1, 7, 'Owned threshold snapshot'),
                (2, 1, 8, 'Owned second match'),
                (3, 2, 7, 'Foreign detection secret'),
            ):
                db.add(models.DetectionResult(
                    id=ident, security_event_id=event_id,
                    detection_config_id=rule_id, rule_name=name,
                    detection_type='Threshold-Based', severity='LOW',
                    match_details='PRIVATE RULE CONDITIONS MUST NOT BE EXPOSED',
                ))
            db.commit()

    def tearDown(self):
        self.client.close()

    def test_user_receives_all_own_matches_only(self):
        response = self.client.get('/security-events')
        self.assertEqual(response.status_code, 200, response.text)
        rows = response.json()
        self.assertEqual(len(rows), 1)
        self.assertEqual([r['rule_name'] for r in rows[0]['configured_detections']],
                         ['Owned threshold snapshot', 'Owned second match'])
        self.assertNotIn('Foreign detection secret', response.text)
        self.assertNotIn('PRIVATE RULE CONDITIONS', response.text)

    def test_foreign_exact_lookup_cannot_expose_matches(self):
        response = self.client.get('/security-events?event_id=merge-event-2')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), [])

    def test_admin_sees_same_saved_snapshot(self):
        user = self.client.get('/security-events?event_id=merge-event-1').json()[0]
        self.select_user(30)
        response = self.client.get('/admin/security-events?event_id=merge-event-1')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(user['configured_detections'], response.json()[0]['configured_detections'])

    def test_unmatched_event_has_empty_list(self):
        with support.Factory() as db:
            db.query(models.DetectionResult).delete()
            db.commit()
        self.assertEqual(self.client.get('/security-events').json()[0]['configured_detections'], [])

    def test_raw_detection_and_severity_are_preserved(self):
        row = self.client.get('/security-events').json()[0]
        self.assertEqual(row['severity'], 'HIGH')
        self.assertIsNone(row['detection']['rule_name'])
        self.assertEqual(row['correlation'], {'count': 2})

    def test_batch_fetch_uses_one_result_query(self):
        from sqlalchemy import event
        statements = []
        def capture(conn, cursor, statement, parameters, context, executemany):
            if 'FROM detection_results' in statement:
                statements.append(statement)
        event.listen(support.engine, 'before_cursor_execute', capture)
        try:
            self.select_user(30)
            response = self.client.get('/admin/security-events')
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(len(response.json()), 2)
            self.assertEqual(len(statements), 1)
        finally:
            event.remove(support.engine, 'before_cursor_execute', capture)


if __name__ == '__main__':
    unittest.main(verbosity=2)
