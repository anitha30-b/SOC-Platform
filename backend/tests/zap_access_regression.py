"""Current ZAP route bodies with actual FastAPI/RBAC, SQLite and mocked ZAP."""
import ast
import asyncio
from datetime import datetime
import __future__
import json
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace as NS
from urllib.parse import urlparse
import unittest
from uuid import uuid4

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['JWT_SECRET_KEY'] = 'isolated-zap-authorization-test'
ROOT = Path(os.environ.get('SOC_TOOL_AUDIT_BACKEND', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tests'))

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy.orm import Session
import rbac
import models
import tool_event_ownership_regression as fixtures

support = fixtures.support
models.SecurityTool.__table__.create(support.engine, checkfirst=True)


def build_routes():
    module = ModuleType('isolated_current_zap_routes')
    sys.modules[module.__name__] = module
    namespace = module.__dict__
    def unused_db():
        raise AssertionError('Test database override was not installed.')
    namespace.update(APIRouter=APIRouter, Depends=Depends, HTTPException=HTTPException,
        BaseModel=BaseModel, Session=Session, User=models.User, Assessment=models.Assessment,
        SecurityFinding=models.SecurityFinding, SecurityTool=models.SecurityTool,
        require_role=rbac.require_role, get_db=unused_db, datetime=datetime, urlparse=urlparse,
        ZAP_JOBS={}, ZAP_SPIDER_JOBS={}, ZAP_URL='http://127.0.0.1:8080',
        seed_security_tools=lambda db: None, generate_finding_id=lambda db: 'ZAP-'+uuid4().hex,
        calculate_risk_level=lambda severity: 'LEVEL_1' if severity in {'HIGH','CRITICAL'} else 'LEVEL_2' if severity=='MEDIUM' else 'LEVEL_3')
    nodes = []
    source = (ROOT/'zap_router.py').read_text(encoding='utf-8')
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'router' for t in node.targets):
            nodes.append(node)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'zap_router.py', 'exec',
        flags=__future__.annotations.compiler_flag), namespace)
    return module, unused_db


class ZapAccessTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ToolEventOwnershipTests()
        self.fixture.setUp()
        with support.Factory() as db:
            if db.query(models.SecurityTool).filter_by(name='OWASP ZAP').first() is None:
                db.add(models.SecurityTool(name='OWASP ZAP', category='Web Application Security'))
                db.commit()
        self.module, dependency = build_routes()
        self.ns = self.module.__dict__
        self.calls = []
        self.permission_calls = []
        self.permission_denied = False
        self.alert_ids = ['11']
        self.alert = {'id': '11', 'pluginId': 'synthetic', 'alert': 'Synthetic information',
            'risk': 'Informational', 'url': 'https://synthetic.invalid/', 'description': 'Test evidence'}
        self.bad_progress = False
        self.bad_cancel = False
        self.status_value = '100'
        self.broken_alert = False
        async def mock_get(path, params=None):
            self.calls.append((path, params))
            if path.endswith('/alerts/'):
                raise AssertionError('Shared site/session alert history must not be read.')
            if path.endswith('/alertsIds/'):
                return {'alertsIds': self.alert_ids}
            if path.endswith('/alert/'):
                return {'alert': {} if self.broken_alert else dict(self.alert)}
            if path.endswith('/status/'):
                return {} if self.bad_progress else {'status': self.status_value}
            if path.endswith('/stop/'):
                return {'code': 'failed'} if self.bad_cancel else {'Result': 'OK'}
            if path.endswith('/scan/'):
                return {'scan': 'same-numeric-id'}
            return {'Result': 'OK'}
        def permission(db, user):
            self.permission_calls.append(user.id)
            if self.permission_denied:
                raise HTTPException(status_code=403, detail='Tool permission denied')
        self.ns['zap_get'] = mock_get
        self.ns['_check_zap_start_permission'] = permission
        self.app = FastAPI()
        self.app.include_router(self.ns['router'])
        self.user_scope = 10
        def current_user(x_test_user: str | None = Header(default=None)):
            if x_test_user is None:
                raise HTTPException(status_code=401, detail='Test login required')
            ident = int(x_test_user)
            return NS(id=ident, client_id=self.user_scope if ident in {1,4} else 20,
                      role_id=3 if ident==9 else 1)
        def session():
            with support.Factory() as db:
                yield db
        self.app.dependency_overrides[rbac.get_current_user] = current_user
        self.app.dependency_overrides[dependency] = session
        self.client = TestClient(self.app)
        self.headers = {'X-Test-User': '1'}
        self.assessment_id = None

    def tearDown(self):
        self.client.close()
        self.fixture.tearDown()

    def start(self, alias=False):
        response = self.client.post('/vapt/zap/'+('active-scan' if alias else 'scan'),
            json={'target':'https://synthetic.invalid'}, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assessment_id = response.json()['assessment_id']
        self.calls.clear()
        return response.json()['scan_id']

    def test_every_route_rejects_missing_login_and_wrong_role_before_io(self):
        operations = [('GET','/status'), ('POST','/scan'), ('GET','/scan/x/progress'),
            ('POST','/scan/x/cancel'), ('GET','/scan/x/results'), ('POST','/active-scan'),
            ('GET','/active-scan/x/progress'), ('GET','/alerts'), ('POST','/active-scan/x/stop'),
            ('POST','/spider'), ('GET','/spider/x/progress')]
        for method, path in operations:
            for headers, expected in (({}, 401), ({'X-Test-User':'9'}, 403)):
                with self.subTest(method=method, path=path, headers=headers):
                    kwargs = {'json':{'target':'https://synthetic.invalid'}} if method=='POST' else {}
                    response = self.client.request(method, '/vapt/zap'+path, headers=headers, **kwargs)
                    self.assertEqual(response.status_code, expected, response.text)
        self.assertFalse(self.calls)

    def test_unknown_and_unowned_legacy_scans_cannot_reach_zap(self):
        self.ns['ZAP_JOBS']['legacy'] = {'user_id':1, 'target':'https://synthetic.invalid', 'assessment_id':15}
        for ident in ('unknown', 'legacy'):
            for method, path in [('GET',f'/scan/{ident}/progress'),('POST',f'/scan/{ident}/cancel'),
                ('GET',f'/scan/{ident}/results'),('GET',f'/active-scan/{ident}/progress'),
                ('POST',f'/active-scan/{ident}/stop'),('GET',f'/spider/{ident}/progress'),
                ('GET',f'/alerts?scan_id={ident}')]:
                response = self.client.request(method, '/vapt/zap'+path, headers=self.headers)
                self.assertEqual(response.status_code, 404, response.text)
        self.assertFalse(self.calls)

    def test_other_owner_even_in_same_client_cannot_read_or_cancel(self):
        ident = self.start()
        for owner in ('2', '4'):
            for method, path in [('GET',f'/scan/{ident}/progress'),('POST',f'/scan/{ident}/cancel'),
                ('GET',f'/scan/{ident}/results'),('GET',f'/alerts?scan_id={ident}')]:
                response = self.client.request(method, '/vapt/zap'+path, headers={'X-Test-User':owner})
                self.assertEqual(response.status_code, 403, response.text)
        self.assertFalse(self.calls)

    def test_changed_customer_scope_cannot_reuse_scan(self):
        ident = self.start()
        self.user_scope = 20
        self.assertEqual(self.client.get(f'/vapt/zap/scan/{ident}/progress',headers=self.headers).status_code,404)
        self.assertFalse(self.calls)

    def test_start_captures_scope_and_legacy_alias_checks_permissions(self):
        self.start(alias=True)
        self.assertEqual(self.permission_calls, [1])
        self.assertEqual(self.ns['ZAP_JOBS']['same-numeric-id']['client_id'], 10)
        self.calls.clear()
        self.permission_denied = True
        for path in ('/scan','/active-scan','/spider'):
            response = self.client.post('/vapt/zap'+path, json={'target':'https://synthetic.invalid'},headers=self.headers)
            self.assertEqual(response.status_code,403)
        self.assertFalse(self.calls)

    def test_spider_and_active_ids_have_separate_ownership(self):
        ident = self.start()
        response = self.client.post('/vapt/zap/spider',json={'target':'https://synthetic.invalid'},headers={'X-Test-User':'2'})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(self.ns['ZAP_JOBS'][ident]['user_id'],1)
        self.assertEqual(self.ns['ZAP_SPIDER_JOBS'][ident]['user_id'],2)
        self.calls.clear()
        self.assertEqual(self.client.get(f'/vapt/zap/spider/{ident}/progress',headers=self.headers).status_code,403)
        self.assertFalse(self.calls)

    def test_info_findings_save_to_owned_assessment_and_replay_without_duplicates(self):
        ident = self.start()
        for _ in range(2):
            response = self.client.get(f'/vapt/zap/scan/{ident}/results',headers=self.headers)
            self.assertEqual(response.status_code,200,response.text)
            row = response.json()['findings'][0]
            self.assertEqual(row['severity'],'INFO')
            self.assertEqual(response.json()['total_findings'],1)
        with support.Factory() as db:
            rows = db.query(models.SecurityFinding).all()
            self.assertEqual(len(rows),1)
            self.assertEqual((rows[0].user_id,rows[0].assessment_id),(1,self.assessment_id))
            self.assertIsNone(rows[0].cvss_score)
        self.assertFalse(any(path.endswith('/alerts/') for path, _ in self.calls))
        self.assertTrue(any(path.endswith('/alertsIds/') and params=={'scanId':ident} for path,params in self.calls))

    def test_unrated_and_valid_zero_alert_results_are_preserved(self):
        ident = self.start()
        self.alert['risk'] = 'unknown'
        response = self.client.get(f'/vapt/zap/scan/{ident}/results',headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['findings'][0]['severity'],'UNRATED')
        self.assertEqual(response.json()['findings'][0]['risk_level'],'UNRATED')
        self.alert_ids = []
        self.assertEqual(self.client.get(f'/vapt/zap/scan/{ident}/results',headers=self.headers).json()['total_alerts'],0)

    def test_malformed_alert_or_id_list_is_not_clean_completion(self):
        ident = self.start()
        for ids, broken in (({},False),(['x'],False),(['11'],True)):
            self.alert_ids, self.broken_alert = ids, broken
            response = self.client.get(f'/vapt/zap/scan/{ident}/results',headers=self.headers)
            self.assertEqual(response.status_code,502,response.text)
        with support.Factory() as db:
            self.assertEqual(db.query(models.SecurityFinding).count(),0)

    def test_missing_or_invalid_progress_does_not_claim_completion(self):
        ident = self.start()
        self.bad_progress = True
        self.assertEqual(self.client.get(f'/vapt/zap/scan/{ident}/progress',headers=self.headers).status_code,502)
        self.bad_progress = False
        self.status_value = '101'
        self.assertEqual(self.client.get(f'/vapt/zap/scan/{ident}/progress',headers=self.headers).status_code,502)

    def test_cancel_requires_confirmation_from_zap(self):
        ident = self.start()
        self.bad_cancel = True
        response = self.client.post(f'/vapt/zap/scan/{ident}/cancel',headers=self.headers)
        self.assertEqual(response.status_code,502,response.text)
        self.assertNotEqual(self.ns['ZAP_JOBS'][ident]['status'],'cancelled')
        self.bad_cancel = False
        self.assertEqual(self.client.post(f'/vapt/zap/active-scan/{ident}/stop',headers=self.headers).status_code,200)

    def test_alerts_require_owned_scan_id_and_matching_target(self):
        ident = self.start()
        self.assertEqual(self.client.get('/vapt/zap/alerts',headers=self.headers).status_code,400)
        self.assertEqual(self.client.get('/vapt/zap/alerts',params={'scan_id':ident,'target':'https://other.invalid'},headers=self.headers).status_code,400)
        self.assertFalse(self.calls)


if __name__ == '__main__':
    unittest.main(verbosity=2)
