"""Real shared workflow/HTTP handlers, SQLite and synthetic DNS records only."""
import ast
import asyncio
from datetime import datetime
import json
import os
from pathlib import Path
import sys
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import urlparse

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['JWT_SECRET_KEY'] = 'isolated-subdomain-fixture-secret-not-for-deployment'
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session
import asset_registration_regression as support
import models
import subdomain_workflow as flow

TABLES = [models.Assessment, models.SubdomainDiscoveryRun, models.SecurityTool,
          models.RoleToolPermission, models.UserToolPermission]
for model in TABLES:
    model.__table__.create(support.engine, checkfirst=True)


def extract(path, names, namespace):
    nodes = [n for n in ast.parse(path.read_text(encoding='utf-8')).body if getattr(n, 'name', None) in names]
    if {n.name for n in nodes} != set(names):
        raise AssertionError('Missing reviewed handlers.')
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(path), 'exec'), namespace)


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.uid = 1
        self.tasks = []
        with support.Factory() as db:
            for model in reversed(TABLES):
                db.query(model).delete()
            for model in reversed(support.TABLE_MODELS):
                db.query(model).delete()
            for cid in (10, 20):
                db.add(support.fixture(models.Client, id=cid))
            for uid, client, role in ((1, 10, 1), (2, 20, 1), (3, None, 1), (4, 10, 1), (5, None, 3)):
                db.add(support.fixture(models.User, id=uid, client_id=client, role_id=role))
            db.add(support.fixture(models.SecurityTool, id=1, name='Subdomain Discovery', enabled=True))
            db.add(support.fixture(models.RoleToolPermission, id=1, role_id=1, tool_id=1, allowed=True))
            db.add(models.Assessment(id=1, user_id=1, target='https://www.example.test'))
            db.commit()
        permission_ns = {'Session': Session, 'User': models.User, 'SecurityTool': models.SecurityTool,
                         'UserToolPermission': models.UserToolPermission, 'RoleToolPermission': models.RoleToolPermission,
                         'func': func, 'HTTPException': HTTPException}
        extract(ROOT / 'vapt.py', ['require_user_tool_permission'], permission_ns)
        self.permission = permission_ns['require_user_tool_permission']
        fake_vapt = ModuleType('vapt')
        fake_vapt.require_user_tool_permission = self.permission
        self.module_patch = patch.dict(sys.modules, {'vapt': fake_vapt})
        self.module_patch.start()

        def db_dependency():
            with support.Factory() as db:
                yield db

        def require_role(role):
            def dependency(db: Session = Depends(db_dependency)):
                owner = db.query(models.User).filter(models.User.id == self.uid).first()
                if not owner or owner.role_id != role:
                    raise HTTPException(403, 'Wrong role')
                return owner
            return dependency

        def task(coro):
            self.tasks.append(True)
            coro.close()

        namespace = {'APIRouter': APIRouter, 'Depends': Depends, 'Query': Query, 'HTTPException': HTTPException,
            'BaseModel': BaseModel, 'Field': Field, 'Session': Session, 'User': models.User,
            'Assessment': models.Assessment, 'SubdomainDiscoveryRun': models.SubdomainDiscoveryRun,
            'get_db': db_dependency, 'require_role': require_role, 'datetime': datetime,
            'urlparse': urlparse, 'asyncio': SimpleNamespace(create_task=task),
            '_run_client_subdomain_discovery': self.no_worker, 'router': APIRouter(prefix='/client')}
        extract(ROOT / 'client_portal.py', ['ClientSubdomainDiscoveryRequest',
            'get_client_subdomain_discovery', 'run_client_subdomain_discovery'], namespace)
        app = FastAPI()
        app.include_router(namespace['router'])
        admin_ns = dict(namespace, router=APIRouter(prefix='/assets'))
        extract(ROOT / 'admin_discovered_servers.py', ['subdomain_discoveries'], admin_ns)
        app.include_router(admin_ns['router'])
        self.client = TestClient(app)

    async def no_worker(self, *args):
        raise AssertionError('No real worker may run in this test.')

    def tearDown(self):
        self.client.close()
        self.module_patch.stop()

    def result(self, records=None, status='completed'):
        return {'status': status, 'json_output': records if records is not None else [
            {'type': 'A', 'name': 'www.example.test', 'address': '192.0.2.10'}]}

    def save(self, uid=1, cid=10, job='synthetic-job', result=None):
        return flow.save_registry_result(support.Factory, result or self.result(), uid, cid, job, 'example.test')

    def test_empty_output_does_not_invent_hosts(self):
        self.assertEqual(flow.parse_discovery('example.test', self.result([]))['discovered_hosts'], [])

    def test_dns_boundaries_invalid_names_and_ipv6_deduplicate(self):
        records = [
            {'type': 'AAAA', 'name': 'V6.EXAMPLE.TEST.', 'address': '2001:db8::1'},
            {'type': 'AAAA', 'name': 'v6.example.test', 'address': '2001:0db8:0:0:0:0:0:1'},
            {'type': 'A', 'name': 'bad name.example.test', 'address': '192.0.2.10'},
            {'type': 'A', 'name': 'example.test.evil.test', 'address': '192.0.2.10'}]
        parsed = flow.parse_discovery('example.test', self.result(records))
        self.assertEqual(parsed['discovered_subdomains'], ['v6.example.test'])
        self.assertEqual(parsed['discovered_ips'], ['2001:db8::1'])
        self.assertEqual(len(parsed['observations']), 1)

    def test_bad_address_and_record_family_are_rejected(self):
        parsed = flow.parse_discovery('example.test', self.result([
            {'type': 'A', 'name': 'bad.example.test', 'address': 'not-an-ip'},
            {'type': 'AAAA', 'name': 'wrong.example.test', 'address': '192.0.2.10'}]))
        self.assertEqual(parsed['discovered_hosts'], [])

    def test_target_rejects_ip_url_and_command_text(self):
        for target in ('127.0.0.1', 'https://example.test', '-d example.test', 'example.test;id'):
            with self.assertRaises(ValueError):
                flow.domain_name(target)

    def test_registry_and_admin_user_share_same_saved_result(self):
        saved = self.save()
        customer = self.client.get('/client/subdomain-discovery').json()['runs'][0]
        self.uid = 5
        admin = self.client.get('/assets/subdomain-discoveries').json()['runs'][0]
        self.assertEqual(customer, admin)
        self.assertEqual(customer['assessment_id'], saved['assessment_id'])
        self.assertEqual(customer['discovery']['discovered_subdomains'], ['www.example.test'])

    def test_zero_findings_history_and_replay_remain_one_run(self):
        first = self.save(result=self.result([]))
        second = self.save(result=self.result())
        self.assertEqual(first['run_id'], second['run_id'])
        self.assertEqual(second['discovery']['discovered_hosts'], [])
        with support.Factory() as db:
            self.assertEqual(db.query(models.SubdomainDiscoveryRun).count(), 1)

    def test_foreign_account_hidden_same_client_sharing_preserved(self):
        self.save()
        self.uid = 2
        self.assertEqual(self.client.get('/client/subdomain-discovery').json()['total'], 0)
        self.uid = 4
        self.assertEqual(self.client.get('/client/subdomain-discovery').json()['total'], 1)

    def test_user_cannot_read_admin_route_admin_cannot_start_user_scan(self):
        self.assertEqual(self.client.get('/assets/subdomain-discoveries').status_code, 403)
        self.uid = 5
        self.assertEqual(self.client.post('/client/subdomain-discovery/run', json={'assessment_id': 1}).status_code, 403)

    def test_explicit_permission_denial_creates_no_job(self):
        with support.Factory() as db:
            db.add(support.fixture(models.UserToolPermission, id=1, user_id=1, tool_id=1, allowed=False))
            db.commit()
        response = self.client.post('/client/subdomain-discovery/run', json={'assessment_id': 1})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.tasks, [])
        with support.Factory() as db:
            self.assertEqual(db.query(models.SubdomainDiscoveryRun).count(), 0)

    def test_foreign_assessment_cannot_start_scan(self):
        self.uid = 2
        response = self.client.post('/client/subdomain-discovery/run', json={'assessment_id': 1})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.tasks, [])

    def test_creation_captures_scope_and_ignores_payload_owner(self):
        response = self.client.post('/client/subdomain-discovery/run',
            json={'assessment_id': 1, 'user_id': 2, 'client_id': 20})
        self.assertEqual(response.status_code, 200, response.text)
        with support.Factory() as db:
            run = db.query(models.SubdomainDiscoveryRun).one()
            self.assertEqual(flow.payload(run)['scope'], {'user_id': 1, 'client_id': 10})
        self.assertEqual(len(self.tasks), 1)

    def test_owner_scope_change_hides_old_run_and_prevents_new_persistence(self):
        self.save()
        with support.Factory() as db:
            db.query(models.User).filter(models.User.id == 1).update({'client_id': 20})
            db.commit()
        self.assertEqual(self.client.get('/client/subdomain-discovery').json()['total'], 0)
        with self.assertRaises(ValueError):
            self.save(job='another-job')

    def test_malformed_completed_output_is_warning_not_clean_success(self):
        summary = self.save(result={'status': 'completed', 'json_output': 'invalid'})
        self.assertEqual(summary['status'], 'completed_with_errors')

    def test_failed_execution_is_not_clean_completion(self):
        self.assertEqual(self.save(result=self.result([], status='timeout'))['status'], 'timeout')

    def test_scope_change_before_execution_does_not_run_scanner(self):
        response = self.client.post('/client/subdomain-discovery/run', json={'assessment_id': 1})
        with support.Factory() as db:
            db.query(models.User).filter(models.User.id == 1).update({'client_id': 20})
            db.commit()
        runner = unittest.mock.Mock(side_effect=AssertionError('Scanner must not run'))
        flow.execute_run(support.Factory, runner, response.json()['run_id'], 'example.test')
        runner.assert_not_called()

    def test_worker_saves_actual_mocked_dns_results(self):
        response = self.client.post('/client/subdomain-discovery/run', json={'assessment_id': 1})
        runner = unittest.mock.Mock(return_value=self.result())
        flow.execute_run(support.Factory, runner, response.json()['run_id'], 'example.test')
        runner.assert_called_once()
        run = self.client.get('/client/subdomain-discovery').json()['runs'][0]
        self.assertEqual(run['status'], 'COMPLETED')
        self.assertEqual(run['discovered_subdomain_count'], 1)

    def test_missing_owner_is_rejected_even_for_zero_results(self):
        with self.assertRaises(ValueError):
            self.save(uid=999, result=self.result([]))

    def test_search_precedes_pagination_and_bounds_are_validated(self):
        self.save()
        response = self.client.get('/client/subdomain-discovery?q=example.test&limit=1')
        self.assertEqual(response.json()['total'], 1)
        self.assertEqual(self.client.get('/client/subdomain-discovery?limit=0').status_code, 422)
        self.assertEqual(self.client.get('/client/subdomain-discovery?q=not-present').json()['total'], 0)

    def generic_namespace(self):
        namespace = {'asyncio': asyncio, 'time': time, 'SessionLocal': support.Factory,
            'GenericToolError': RuntimeError, 'run_generic_tool': lambda **kwargs: self.result(),
            'GENERIC_TOOL_JOBS': {'synthetic-generic': {'user_id': 1, 'client_id': 10}}}
        extract(ROOT / 'vapt_registry_router.py', ['_run_generic_job'], namespace)
        return namespace

    def test_actual_generic_worker_persists_captured_scope(self):
        namespace = self.generic_namespace()
        with patch.object(flow, 'save_registry_result', return_value={
                'discovery': {'discovered_subdomains': ['www.example.test']},
                'assessment_id': 7, 'run_id': 8, 'status': 'completed'}) as save:
            asyncio.run(namespace['_run_generic_job']('synthetic-generic',
                {'id': 'subdomain-discovery', 'name': 'Subdomain Discovery'}, 'example.test'))
            self.assertEqual(save.call_args.args[2:], (1, 10, 'synthetic-generic', 'example.test'))
        job = namespace['GENERIC_TOOL_JOBS']['synthetic-generic']
        self.assertEqual(job['result']['persistence']['status'], 'saved')
        self.assertEqual(job['result']['discovery_run_id'], 8)

    def test_actual_generic_worker_storage_failure_is_warning(self):
        namespace = self.generic_namespace()
        with patch.object(flow, 'save_registry_result', side_effect=RuntimeError('synthetic storage failure')):
            asyncio.run(namespace['_run_generic_job']('synthetic-generic',
                {'id': 'subdomain-discovery', 'name': 'Subdomain Discovery'}, 'example.test'))
        job = namespace['GENERIC_TOOL_JOBS']['synthetic-generic']
        self.assertEqual(job['status'], 'completed_with_errors')
        self.assertEqual(job['result']['persistence']['status'], 'failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
