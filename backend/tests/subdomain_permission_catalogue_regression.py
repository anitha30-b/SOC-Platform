"""SQLite and real admin permission handler bodies; no app or live database."""
import ast
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['JWT_SECRET_KEY'] = 'isolated-subdomain-catalogue-not-for-deployment'
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
import asset_registration_regression as support
import models
import rbac
from subdomain_tool_catalogue import TOOL, ensure_subdomain_tool

EXTRA = [models.Role, models.SecurityTool, models.UserToolPermission, models.RoleToolPermission]
for model in EXTRA:
    model.__table__.create(support.engine, checkfirst=True)


def constant(path, name):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    return ast.literal_eval(next(n.value for n in tree.body if isinstance(n, ast.Assign) and
        any(isinstance(t, ast.Name) and t.id == name for t in n.targets)))


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.role = 3
        with support.Factory() as db:
            for model in reversed(EXTRA):
                db.query(model).delete()
            for model in reversed(support.TABLE_MODELS):
                db.query(model).delete()
            db.add(support.fixture(models.Role, id=1, name='Client'))
            db.add(support.fixture(models.User, id=1, role_id=1))
            db.commit()
        def get_db():
            with support.Factory() as db:
                yield db
        names = constant(ROOT / 'admin.py', 'VAPT_PERMISSION_TOOL_NAMES')
        namespace = {'Depends': Depends, 'Session': Session, 'User': models.User,
            'SecurityTool': models.SecurityTool, 'UserToolPermission': models.UserToolPermission,
            'RoleToolPermission': models.RoleToolPermission, 'Role': models.Role,
            'VAPT_PERMISSION_TOOL_NAMES': names, 'require_role': rbac.require_role, 'get_db': get_db}
        from fastapi import HTTPException
        namespace['HTTPException'] = HTTPException
        wanted = {'get_security_tools_for_permissions', 'get_user_tool_permissions', 'get_role_tool_permissions'}
        nodes = [n for n in ast.parse((ROOT / 'admin.py').read_text(encoding='utf-8')).body if getattr(n, 'name', None) in wanted]
        self.assertEqual({n.name for n in nodes}, wanted)
        for node in nodes:
            node.decorator_list = []
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<admin-catalogue-handlers>', 'exec'), namespace)
        app = FastAPI()
        app.dependency_overrides[rbac.get_current_user] = lambda: SimpleNamespace(id=99, role_id=self.role)
        app.get('/tools')(namespace['get_security_tools_for_permissions'])
        app.get('/users/{user_id}')(namespace['get_user_tool_permissions'])
        app.get('/roles/{role_id}')(namespace['get_role_tool_permissions'])
        getter = next(n for n in ast.parse((ROOT / 'vapt.py').read_text(encoding='utf-8')).body
                      if isinstance(n, ast.FunctionDef) and n.name == 'get_my_tool_permissions')
        getter.decorator_list = []
        exec(compile(ast.fix_missing_locations(ast.Module(body=[getter], type_ignores=[])), '<user-effective-permissions>', 'exec'), namespace)
        app.get('/mine')(namespace['get_my_tool_permissions'])
        app.dependency_overrides[rbac.get_current_user] = lambda: SimpleNamespace(id=1, role_id=self.role)
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()

    def register(self):
        with support.Factory() as db:
            summary = ensure_subdomain_tool(db)
            db.commit()
            return summary

    def test_fresh_catalogue_and_admin_allowlist_include_tool(self):
        self.assertIn(TOOL['name'], constant(ROOT / 'admin.py', 'VAPT_PERMISSION_TOOL_NAMES'))
        entries = constant(ROOT / 'security_findings.py', 'SECURITY_TOOLS')
        self.assertEqual(sum(row['name'] == TOOL['name'] for row in entries), 1)

    def test_admin_tools_endpoint_lists_registered_tool(self):
        summary = self.register()
        response = self.client.get('/tools')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIn(summary['tool_id'], [row['id'] for row in response.json()])

    def test_user_and_role_permission_lists_default_to_no_grant(self):
        self.register()
        user = next(row for row in self.client.get('/users/1').json() if row['tool_name'] == TOOL['name'])
        role = next(row for row in self.client.get('/roles/1').json()['permissions'] if row['tool_name'] == TOOL['name'])
        self.assertEqual(user['permission_state'], 'inherit')
        self.assertFalse(user['allowed'])
        self.assertFalse(role['allowed'])

    def test_registration_is_idempotent_and_changes_no_permissions(self):
        first = self.register()
        with support.Factory() as db:
            db.add(models.UserToolPermission(user_id=1, tool_id=first['tool_id'], allowed=False))
            db.add(models.RoleToolPermission(role_id=1, tool_id=first['tool_id'], allowed=True))
            db.commit()
        second = self.register()
        self.assertEqual(first['tool_id'], second['tool_id'])
        with support.Factory() as db:
            self.assertEqual(db.query(models.SecurityTool).count(), 1)
            self.assertFalse(db.query(models.UserToolPermission).one().allowed)
            self.assertTrue(db.query(models.RoleToolPermission).one().allowed)
        user = next(row for row in self.client.get('/users/1').json() if row['tool_name'] == TOOL['name'])
        self.assertEqual(user['permission_state'], 'deny')

    def test_existing_disabled_tool_is_not_reenabled(self):
        first = self.register()
        with support.Factory() as db:
            db.query(models.SecurityTool).filter(models.SecurityTool.id == first['tool_id']).update({'enabled': False})
            db.commit()
        self.assertFalse(self.register()['enabled'])
        self.assertEqual(self.client.get('/tools').json(), [])

    def test_client_cannot_read_admin_permission_endpoints(self):
        self.register()
        self.role = 1
        for path in ('/tools', '/users/1', '/roles/1'):
            self.assertEqual(self.client.get(path).status_code, 403)

    def test_user_effective_permissions_follow_role_grant_and_individual_deny(self):
        tool = self.register()
        with support.Factory() as db:
            db.add(models.RoleToolPermission(role_id=1, tool_id=tool['tool_id'], allowed=True))
            db.commit()
        self.role = 1
        row = next(row for row in self.client.get('/mine').json() if row['tool_name'] == TOOL['name'])
        self.assertTrue(row['allowed'])
        self.assertEqual(row['permission_state'], 'inherit')
        with support.Factory() as db:
            db.add(models.UserToolPermission(user_id=1, tool_id=tool['tool_id'], allowed=False))
            db.commit()
        row = next(row for row in self.client.get('/mine').json() if row['tool_name'] == TOOL['name'])
        self.assertFalse(row['allowed'])
        self.assertEqual(row['permission_state'], 'deny')


if __name__ == '__main__':
    unittest.main(verbosity=2)
