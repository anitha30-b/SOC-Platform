"""Actual generic HTTP handlers with real role checks and synthetic jobs.

Extract only the registry handlers: importing the full module would import
collector/scanner modules. No scanner, database session or production app runs.
HTTP identity is overridden; this suite does not test JWT/session validation.
"""
import ast
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
import uuid

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['JWT_SECRET_KEY'] = 'isolated-generic-job-test-only-not-for-deployment'
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy.orm import Session
import models
import rbac


class GenericJobAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.identity = SimpleNamespace(id=1, client_id=10, role_id=1, username='fixture-owner')
        self.jobs = {}
        self.worker_calls = []
        self.permission = Mock()
        def get_db():
            yield None
        async def fake_worker(job_id, tool, target):
            self.worker_calls.append((job_id, tool['id'], target))
        tool = {'id': 'dig', 'name': 'Dig', 'enabled': True,
                'target_types': ['domain'], 'executable': 'synthetic-not-executed'}
        self.namespace = {
            '__name__': 'isolated_registry_http',
            'APIRouter': APIRouter, 'Depends': Depends, 'HTTPException': HTTPException,
            'BaseModel': BaseModel, 'Session': Session, 'User': models.User,
            'get_db': get_db, 'require_role': rbac.require_role,
            'require_user_tool_permission': self.permission,
            'router': APIRouter(prefix='/vapt/registry'),
            'build_registry': lambda: {'tools': [tool]},
            'GENERIC_TOOL_JOBS': self.jobs, '_run_generic_job': fake_worker,
            'uuid': uuid, 'time': time, 'asyncio': __import__('asyncio'),
        }
        wanted = {'GenericToolRunRequest', '_get_registry_tool', '_generic_target_type',
                  '_new_generic_job', 'run_registry_tool_async', 'get_registry_tool_progress'}
        source = ROOT / 'vapt_registry_router.py'
        nodes = [node for node in ast.parse(source.read_text(encoding='utf-8')).body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                 and node.name in wanted]
        self.assertEqual({node.name for node in nodes}, wanted)
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     str(source), 'exec'), self.namespace)
        self.app = FastAPI()
        self.app.include_router(self.namespace['router'])
        self.app.dependency_overrides[rbac.get_current_user] = lambda: self.identity
        self.client = TestClient(self.app)
        self.jobs['owned'] = {
            'job_id': 'owned', 'tool': 'dig', 'user_id': 1,
            'target': 'synthetic.invalid', 'status': 'completed', 'progress': 100,
            'result': {'fixture': 'private-synthetic-result'},
        }

    def tearDown(self):
        self.client.close()

    def progress(self, job='owned', tool='dig'):
        return self.client.get(f'/vapt/registry/tools/{tool}/progress/{job}')

    def test_owner_reads_result(self):
        response = self.progress()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['result']['fixture'], 'private-synthetic-result')

    def test_same_client_other_user_cannot_read_private_scan(self):
        self.identity.id = 2
        response = self.progress()
        self.assertEqual(response.status_code, 404, response.text)
        self.assertNotIn('private-synthetic-result', response.text)

    def test_other_client_cannot_read_result(self):
        self.identity.id, self.identity.client_id = 2, 20
        self.assertEqual(self.progress().status_code, 404)

    def test_unowned_legacy_job_is_hidden(self):
        self.jobs['owned'].pop('user_id')
        self.assertEqual(self.progress().status_code, 404)

    def test_wrong_tool_and_unknown_job_are_hidden(self):
        self.assertEqual(self.progress(tool='whois').status_code, 404)
        self.assertEqual(self.progress(job='unknown').status_code, 404)

    def test_creation_uses_authenticated_owner_not_payload(self):
        response = self.client.post('/vapt/registry/tools/dig/run-async', json={
            'target': 'synthetic.invalid', 'user_id': 999, 'owner_user_id': 999,
        })
        self.assertEqual(response.status_code, 200, response.text)
        job = self.jobs[response.json()['job_id']]
        self.assertEqual(job['user_id'], 1)
        self.permission.assert_called_once()

    def test_permission_denial_creates_no_job(self):
        self.permission.side_effect = HTTPException(status_code=403, detail='fixture denied')
        response = self.client.post('/vapt/registry/tools/dig/run-async', json={'target': 'synthetic.invalid'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(set(self.jobs), {'owned'})
        self.assertEqual(self.worker_calls, [])

    def test_wrong_roles_cannot_read_or_start(self):
        for role in (2, 3, 99):
            self.identity.role_id = role
            self.assertEqual(self.progress().status_code, 403)
            response = self.client.post('/vapt/registry/tools/dig/run-async', json={'target': 'synthetic.invalid'})
            self.assertEqual(response.status_code, 403)
        self.assertEqual(set(self.jobs), {'owned'})

    def test_invalid_owner_never_creates_job(self):
        for owner in (None, 0, -1, True, '1'):
            with self.assertRaises(ValueError):
                self.namespace['_new_generic_job']('dig', 'synthetic.invalid', owner)
        self.assertEqual(set(self.jobs), {'owned'})

    def test_missing_owner_argument_is_not_optional(self):
        with self.assertRaises(TypeError):
            self.namespace['_new_generic_job']('dig', 'synthetic.invalid')


if __name__ == '__main__':
    unittest.main(verbosity=2)
