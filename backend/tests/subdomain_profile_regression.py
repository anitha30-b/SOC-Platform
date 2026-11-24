"""Profile runner/HTTP fixtures only; never execute DNSRecon or query DNS."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(os.environ.get('SOC_SCAN_AUDIT_BACKEND', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
import subdomain_profiles as profiles


class ProfileRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.full = root / 'full.txt'
        self.quick = root / 'quick.txt'
        self.full.write_text('\n'.join('host' + str(i) for i in range(5000)) + '\n', encoding='utf-8')
        self.quick.write_text('\n'.join('host' + str(i) for i in range(250)) + '\n', encoding='utf-8')
        self.paths = patch.multiple(profiles, FULL_WORDLIST=self.full, QUICK_WORDLIST=self.quick)
        self.paths.start()
        spec = importlib.util.spec_from_file_location('isolated_subdomain_profile_runner', ROOT / 'vapt_tools/generic_runner.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.calls = []
        self.budgets = []

    def tearDown(self):
        self.paths.stop()
        self.temp.cleanup()

    def run_fixture(self, profile='full', timeout=False, timeout_seconds=300):
        process = SimpleNamespace(returncode=0)
        count = [0]
        def communicate(**kwargs):
            count[0] += 1
            if 'timeout' in kwargs:
                self.budgets.append(kwargs['timeout'])
            if timeout and count[0] == 1:
                raise subprocess.TimeoutExpired('fixture-only', kwargs['timeout'])
            return 'synthetic DNS output', ''
        process.communicate = communicate
        def kill():
            process.returncode = -9
        process.kill = kill
        def popen(command, **kwargs):
            self.calls.append(command)
            Path(command[command.index('-j') + 1]).write_text('[]', encoding='utf-8')
            return process
        with patch.object(self.module, 'resolve_executable', return_value='fixture-not-executed'), \
             patch.object(self.module.subprocess, 'Popen', side_effect=popen):
            return self.module.run_generic_tool(tool_id='subdomain-discovery', tool_name='Subdomain Discovery',
                executable='fixture', target='www.example.test', execution_type='scanner',
                timeout_seconds=timeout_seconds, discovery_profile=profile)

    def test_default_full_keeps_full_dictionary_and_budget(self):
        result = self.run_fixture()
        command = self.calls[0]
        self.assertEqual(command[command.index('-D') + 1], str(self.full))
        self.assertEqual(self.budgets, [300])
        self.assertEqual(result['candidate_count'], 5000)
        self.assertEqual(result['discovery_profile'], 'full')

    def test_quick_uses_250_name_dictionary_and_shorter_budget(self):
        result = self.run_fixture('quick')
        command = self.calls[0]
        self.assertEqual(command[command.index('-D') + 1], str(self.quick))
        self.assertEqual(self.budgets, [60])
        self.assertEqual(result['candidate_count'], 250)
        self.assertIn('Limited', result['coverage'])
        self.assertGreaterEqual(result['elapsed_seconds'], 0)

    def test_target_and_lookup_mode_do_not_expand(self):
        self.run_fixture('quick')
        self.assertEqual(self.calls[0][self.calls[0].index('-d') + 1], 'www.example.test')
        self.assertEqual(self.calls[0][self.calls[0].index('-t') + 1], 'brt')

    def test_quick_timeout_is_not_reported_completed(self):
        result = self.run_fixture('quick', timeout=True)
        self.assertEqual(result['status'], 'timeout')
        self.assertEqual(result['discovery_profile'], 'quick')
        self.assertEqual(result['return_code'], -9)

    def test_shorter_existing_budget_is_preserved(self):
        result = self.run_fixture('quick', timeout_seconds=10)
        self.assertEqual(self.budgets, [10])
        self.assertEqual(result['timeout_seconds'], 10)

    def test_invalid_profile_does_not_execute(self):
        with self.assertRaises(ValueError):
            self.run_fixture('../../any-file')
        self.assertEqual(self.calls, [])

    def test_missing_quick_dictionary_does_not_execute(self):
        self.quick.unlink()
        with self.assertRaises(ValueError):
            self.run_fixture('quick')
        self.assertEqual(self.calls, [])

    def test_oversized_quick_dictionary_is_rejected(self):
        self.quick.write_text('\n'.join('host' + str(i) for i in range(251)))
        with self.assertRaises(ValueError):
            self.run_fixture('quick')
        self.assertEqual(self.calls, [])


class ProfileHTTPTests(unittest.TestCase):
    def setUp(self):
        import generic_tool_job_authorization_regression as auth
        self.base = auth.GenericJobAuthorizationTests()
        self.base.setUp()
        self.base.namespace['build_registry'] = lambda: {'tools': [{
            'id': 'subdomain-discovery', 'name': 'Subdomain Discovery', 'enabled': True,
            'target_types': ['domain'], 'executable': 'fixture-not-executed'}]}
        node = next(n for n in ast.parse((ROOT / 'vapt_registry_router.py').read_text(encoding='utf-8')).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'get_subdomain_profiles')
        node.decorator_list = []
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), '<profile-capabilities>', 'exec'), self.base.namespace)
        self.base.app.get('/vapt/registry/subdomain-profiles')(self.base.namespace['get_subdomain_profiles'])

    def tearDown(self):
        self.base.tearDown()

    def post(self, **payload):
        return self.base.client.post('/vapt/registry/tools/subdomain-discovery/run-async',
                                     json={'target': 'www.example.test', **payload})

    def test_default_request_keeps_full(self):
        response = self.post()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.base.jobs[response.json()['job_id']]['discovery_profile'], 'full')

    def test_explicit_quick_is_captured_with_authenticated_owner(self):
        response = self.post(discovery_profile='quick', user_id=999, wordlist='/etc/passwd')
        self.assertEqual(response.status_code, 200, response.text)
        job = self.base.jobs[response.json()['job_id']]
        self.assertEqual(job['discovery_profile'], 'quick')
        self.assertEqual(job['user_id'], 1)
        self.assertNotIn('wordlist', job)

    def test_invalid_profile_creates_no_job(self):
        response = self.post(discovery_profile='arbitrary')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.base.jobs), 1)
        self.assertEqual(self.base.worker_calls, [])

    def test_quick_does_not_bypass_permission_denial(self):
        from fastapi import HTTPException
        self.base.permission.side_effect = HTTPException(403, 'Fixture permission denied')
        self.assertEqual(self.post(discovery_profile='quick').status_code, 403)
        self.assertEqual(len(self.base.jobs), 1)

    def test_profile_capabilities_require_tool_permission_and_hide_paths(self):
        response = self.base.client.get('/vapt/registry/subdomain-profiles')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['version'], 1)
        self.assertEqual(response.json()['default'], 'full')
        self.assertEqual([row['profile'] for row in response.json()['profiles']], ['full', 'quick'])
        self.assertTrue(all('wordlist' not in row for row in response.json()['profiles']))
        from fastapi import HTTPException
        self.base.permission.side_effect = HTTPException(403, 'Fixture permission denied')
        self.assertEqual(self.base.client.get('/vapt/registry/subdomain-profiles').status_code, 403)


if __name__ == '__main__':
    unittest.main(verbosity=2)
