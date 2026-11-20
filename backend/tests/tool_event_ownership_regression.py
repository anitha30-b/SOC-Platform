"""Actual persistence functions and event store against isolated SQLite fixtures.

Only persistence functions are extracted, so scanner/collector modules never
load. Detection evaluation and publication are stubbed; no external I/O occurs.
"""
import ast
from copy import deepcopy
import inspect
import json
import os
from pathlib import Path
import re
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['JWT_SECRET_KEY'] = 'isolated-tool-event-regression-not-for-deployment'
ROOT = Path(os.environ.get('SOC_TOOL_AUDIT_BACKEND', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))

import asset_registration_regression as support
import models
from security_events import create_security_event, generate_event_id
from security_event_store import store_security_event

models.SecurityEvent.__table__.create(support.engine, checkfirst=True)


class ToolEventOwnershipTests(unittest.TestCase):
    def setUp(self):
        with support.Factory() as db:
            db.query(models.SecurityEvent).delete()
            for model in reversed(support.TABLE_MODELS):
                db.query(model).delete()
            for client in (10, 20):
                db.add(support.fixture(models.Client, id=client))
            for uid, client in ((1, 10), (2, 20), (3, None), (4, 10)):
                db.add(support.fixture(models.User, id=uid, client_id=client, role_id=1))
            db.commit()
        self.notifications = []
        fake_detection = ModuleType('detection_engine')
        fake_detection.evaluate_event = lambda db, event: {'detections_matched': 0, 'alerts_generated': 0}
        self.detection_patch = patch.dict(sys.modules, {'detection_engine': fake_detection})
        self.detection_patch.start()
        self.functions = {}
        for tool, filename, function in (
            ('nuclei', 'vapt_registry_router.py', '_persist_nuclei_security_events'),
            ('masscan', 'vapt.py', 'persist_masscan_security_events'),
        ):
            node = next(node for node in ast.parse((ROOT / filename).read_text(encoding='utf-8')).body
                        if isinstance(node, ast.FunctionDef) and node.name == function)
            namespace = {
                'json': json, 're': re, 'SessionLocal': support.Factory,
                'SecurityEvent': models.SecurityEvent, 'User': models.User,
                'store_security_event': store_security_event,
                'create_security_event': create_security_event, 'generate_event_id': generate_event_id,
                'notify_security_event': lambda event: self.notifications.append(deepcopy(event)),
            }
            exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                         str(ROOT / filename), 'exec'), namespace)
            self.functions[tool] = namespace[function]

    def tearDown(self):
        self.detection_patch.stop()

    def result(self, tool):
        if tool == 'nuclei':
            return {'status': 'completed', 'target': 'https://synthetic.invalid',
                    'findings': [{'name': 'Synthetic finding', 'template_id': 'fixture-only',
                                  'severity': 'medium', 'matched_at': 'https://synthetic.invalid/test'}]}
        return {'status': 'completed', 'target': '192.0.2.10',
                'results': {'open_ports': [{'host': '192.0.2.10', 'port': 443,
                                            'protocol': 'tcp', 'state': 'open'}]}}

    def persist(self, tool, user_id=1, result=None):
        function = self.functions[tool]
        parameters = inspect.signature(function).parameters
        args = {}
        # Allow this suite to demonstrate the old missing-ownership contract.
        if 'user_id' in parameters:
            args['user_id'] = user_id
        if 'client_id' in parameters:
            args['client_id'] = {1: 10, 2: 20, 3: None, 4: 10}[user_id]
        return function(deepcopy(result if result is not None else self.result(tool)), **args)

    def rows(self, tool):
        with support.Factory() as db:
            return [(row.owner_user_id, row.client_id, row.event_id)
                    for row in db.query(models.SecurityEvent).filter(models.SecurityEvent.source == tool).all()]

    def test_saved_findings_keep_initiating_user_and_client(self):
        for tool in self.functions:
            with self.subTest(tool=tool):
                self.assertEqual(self.persist(tool), 1)
                self.assertEqual(self.rows(tool)[0][:2], (1, 10))

    def test_identical_findings_from_two_accounts_remain_distinct(self):
        for tool in self.functions:
            with self.subTest(tool=tool):
                self.persist(tool, 1)
                self.persist(tool, 2)
                rows = self.rows(tool)
                self.assertEqual(len(rows), 2)
                self.assertEqual({row[:2] for row in rows}, {(1, 10), (2, 20)})
                self.assertEqual(len({row[2] for row in rows}), 2)

    def test_same_owner_replay_does_not_duplicate(self):
        for tool in self.functions:
            with self.subTest(tool=tool):
                self.assertEqual(self.persist(tool), 1)
                self.assertEqual(self.persist(tool), 0)
                self.assertEqual(len(self.rows(tool)), 1)

    def test_published_event_keeps_the_same_owner(self):
        for tool in self.functions:
            with self.subTest(tool=tool):
                self.persist(tool)
                event = self.notifications[-1]
                self.assertEqual((event.get('owner_user_id'), event.get('client_id')), (1, 10))

    def test_personal_account_has_owner_without_client(self):
        for tool in self.functions:
            with self.subTest(tool=tool):
                self.persist(tool, 3)
                self.assertEqual(self.rows(tool)[0][:2], (3, None))

    def test_result_payload_cannot_choose_another_owner(self):
        for tool in self.functions:
            with self.subTest(tool=tool):
                result = self.result(tool)
                result.update(owner_user_id=2, user_id=2, client_id=20)
                self.persist(tool, 1, result)
                self.assertEqual(self.rows(tool)[0][:2], (1, 10))

    def test_same_client_different_initiators_keep_distinct_events(self):
        for tool in self.functions:
            with self.subTest(tool=tool):
                self.persist(tool, 1)
                self.persist(tool, 4)
                self.assertEqual({row[:2] for row in self.rows(tool)}, {(1, 10), (4, 10)})

    def test_unknown_account_cannot_save_or_publish(self):
        for tool, function in self.functions.items():
            with self.subTest(tool=tool):
                with self.assertRaises(ValueError):
                    function(self.result(tool), user_id=999, client_id=10)
                self.assertEqual(self.rows(tool), [])
        self.assertEqual(self.notifications, [])

    def test_changed_client_scope_cannot_take_over_old_job(self):
        with support.Factory() as db:
            db.get(models.User, 1).client_id = 20
            db.commit()
        for tool, function in self.functions.items():
            with self.subTest(tool=tool):
                with self.assertRaises(ValueError):
                    function(self.result(tool), user_id=1, client_id=10)
                self.assertEqual(self.rows(tool), [])
        self.assertEqual(self.notifications, [])

    def test_missing_or_invalid_owner_is_rejected(self):
        for tool, function in self.functions.items():
            with self.subTest(tool=tool):
                for owner in (None, 0, -1, True, '1'):
                    with self.assertRaises(ValueError):
                        function(self.result(tool), user_id=owner, client_id=10)
                self.assertEqual(self.rows(tool), [])
        self.assertEqual(self.notifications, [])

    def test_all_job_constructors_capture_server_scope(self):
        for filename, name, positional in (
            ('vapt_registry_router.py', '_new_nuclei_job', ('synthetic.invalid', 1, 10)),
            ('vapt_registry_router.py', '_new_generic_job', ('dig', 'synthetic.invalid', 1, 10)),
            ('vapt.py', '_new_masscan_job', ('synthetic.invalid', 1, 10)),
        ):
            with self.subTest(constructor=name):
                node = next(node for node in ast.parse((ROOT / filename).read_text(encoding='utf-8')).body
                            if isinstance(node, ast.FunctionDef) and node.name == name)
                jobs = {}
                namespace = {'uuid': __import__('uuid'), 'time': __import__('time'),
                             'NUCLEI_JOBS': jobs, 'GENERIC_TOOL_JOBS': jobs, 'MASSCAN_JOBS': jobs,
                             '_persist_background_job': lambda *args: None}
                exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])),
                             str(ROOT / filename), 'exec'), namespace)
                job_id = namespace[name](*positional)
                self.assertEqual((jobs[job_id]['user_id'], jobs[job_id]['client_id']), (1, 10))


if __name__ == '__main__':
    unittest.main(verbosity=2)
