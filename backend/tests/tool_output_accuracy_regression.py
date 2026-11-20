"""Recorded fixture checks; subprocess entry points are replaced, never executed."""
import ast
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(os.environ.get('SOC_SCAN_AUDIT_BACKEND', Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(ROOT))
EMPTY_XML = '<nmaprun><runstats><finished exit="success" elapsed="1"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>'
HOST_XML = '''<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="FixtureServer" version="1.2" tunnel="ssl"/>
<script id="ssl-cert" output="Synthetic certificate evidence"/></port>
<port protocol="tcp" portid="22"><state state="closed"/></port></ports></host>
<runstats><finished exit="success" elapsed="1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NmapOutputTests(unittest.TestCase):
    def setUp(self):
        source = ROOT / 'vapt.py'
        names = {'_parse_nmap_script', 'parse_nmap_xml', '_extract_open_ports', '_execute_nmap_command'}
        nodes = [node for node in ast.parse(source.read_text(encoding='utf-8')).body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
        self.assertEqual({node.name for node in nodes}, names)
        self.namespace = {
            'ET': ET, 'os': os, 'time': time, 'asyncio': asyncio,
            'NMAP_PATH': str(source), 'validate_nmap_target': lambda value: value,
            'NMAP_PROFILES': {key: {'profile': key} for key in ('quick', 'service')},
            'NMAP_QUICK_TIMEOUT': 1, 'NMAP_SERVICE_TIMEOUT': 1,
            '_nmap_rate_args': lambda: [],
        }
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                     str(source), 'exec'), self.namespace)

    def run_fixture(self, xml=EMPTY_XML, code=0, timed_out=False, profile='quick'):
        async def fake_pass(*args, **kwargs):
            return {'xml': xml, 'return_code': code, 'timed_out': timed_out}
        self.namespace['_run_nmap_pass'] = fake_pass
        return asyncio.run(self.namespace['_execute_nmap_command']('192.0.2.10', profile))

    def test_valid_empty_scan_is_completed(self):
        for profile in ('quick', 'service'):
            with self.subTest(profile=profile):
                result = self.run_fixture(profile=profile)
                self.assertEqual(result['status'], 'completed')
                self.assertEqual(result['results']['host_count'], 0)

    def test_nonzero_exit_is_not_clean_completion(self):
        for profile in ('quick', 'service'):
            with self.subTest(profile=profile):
                self.assertNotEqual(self.run_fixture(code=2, profile=profile)['status'], 'completed')

    def test_timeout_is_not_clean_completion(self):
        for profile in ('quick', 'service'):
            with self.subTest(profile=profile):
                self.assertNotEqual(self.run_fixture(code=-9, timed_out=True, profile=profile)['status'], 'completed')

    def test_malformed_xml_is_not_clean_completion(self):
        for profile in ('quick', 'service'):
            with self.subTest(profile=profile):
                self.assertNotEqual(self.run_fixture(xml='<nmaprun><host>', profile=profile)['status'], 'completed')

    def test_wrong_xml_document_is_not_clean_completion(self):
        for profile in ('quick', 'service'):
            with self.subTest(profile=profile):
                self.assertNotEqual(self.run_fixture(xml='<unrelated/>', profile=profile)['status'], 'completed')

    def test_nmap_reported_error_is_not_clean_completion(self):
        xml = '<nmaprun><runstats><finished exit="error" errormsg="Synthetic failure"/></runstats></nmaprun>'
        for profile in ('quick', 'service'):
            with self.subTest(profile=profile):
                self.assertNotEqual(self.run_fixture(xml=xml, profile=profile)['status'], 'completed')

    def test_service_and_script_evidence_survive_parsing(self):
        result = self.run_fixture(xml=HOST_XML, profile='service')
        host = result['results']['hosts'][0]
        port = host['ports'][0]
        self.assertEqual(port['port'], 443)
        self.assertEqual(port['service']['version'], '1.2')
        self.assertEqual(port['scripts'][0]['output'], 'Synthetic certificate evidence')

    def test_closed_ports_do_not_become_open_findings(self):
        result = self.run_fixture(xml=HOST_XML)
        self.assertEqual(len(result['open_ports']), 1)

    def test_failure_progress_does_not_claim_clean_completion(self):
        async def fake_pass(*args, **kwargs):
            return {'xml': EMPTY_XML, 'return_code': 2, 'timed_out': False}
        async def capture(percent, stage):
            messages.append(stage)
        self.namespace['_run_nmap_pass'] = fake_pass
        for profile in ('quick', 'service'):
            messages = []
            result = asyncio.run(self.namespace['_execute_nmap_command'](
                '192.0.2.10', profile, progress_callback=capture))
            self.assertNotEqual(result['status'], 'completed')
            self.assertIn('error', messages[-1].lower())


class NucleiOutputTests(unittest.TestCase):
    def setUp(self):
        self.module = load_file('isolated_nuclei_output', ROOT / 'vapt_tools/scripts/nuclei.py')

    def run_fixture(self, output='', code=0):
        completed = SimpleNamespace(stdout=output, stderr='', returncode=code)
        with patch.object(self.module, 'check_nuclei', return_value='synthetic-not-executed'), \
             patch.object(self.module.subprocess, 'run', return_value=completed):
            return self.module.run_nuclei('https://synthetic.invalid')

    def test_zero_findings_can_be_valid_success(self):
        result = self.run_fixture()
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['finding_count'], 0)

    def test_nonzero_exit_is_not_clean_completion(self):
        self.assertNotEqual(self.run_fixture(code=2)['status'], 'completed')

    def test_malformed_jsonl_is_not_clean_empty_success(self):
        self.assertNotEqual(self.run_fixture(output='{"template-id": broken-json}\n')['status'], 'completed')

    def test_real_fields_survive_normalization(self):
        fixture = {'template-id': 'fixture-template', 'matched-at': 'https://synthetic.invalid/a',
                   'info': {'name': 'Fixture only', 'severity': 'high',
                            'classification': {'cve-id': ['CVE-2099-0001'], 'cwe-id': ['CWE-79']}}}
        row = self.run_fixture(output=json.dumps(fixture))['findings'][0]
        self.assertEqual(row['severity'], 'HIGH')
        self.assertEqual(row['cve'], ['CVE-2099-0001'])
        self.assertEqual(row['raw'], fixture)

    def test_timeout_is_reported_as_an_error(self):
        with patch.object(self.module, 'check_nuclei', return_value='synthetic-not-executed'), \
             patch.object(self.module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixture', 1)):
            with self.assertRaises(self.module.NucleiError):
                self.module.run_nuclei('https://synthetic.invalid', timeout_seconds=1)

    def test_mixed_output_preserves_valid_findings_and_reports_corruption(self):
        valid = {'template-id': 'fixture', 'info': {'name': 'Fixture', 'severity': 'low'}}
        result = self.run_fixture(json.dumps(valid) + '\n{"broken": bad}\n')
        self.assertEqual(result['finding_count'], 1)
        self.assertEqual(result['findings'][0]['raw'], valid)
        self.assertNotEqual(result['status'], 'completed')
        self.assertTrue(result['parse_errors'])

    def test_informational_banner_is_not_a_finding(self):
        result = self.run_fixture('[INF] Synthetic informational banner\n')
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['finding_count'], 0)

    def test_invalid_finding_structure_is_not_clean_success(self):
        malformed = {'template-id': 'fixture', 'info': 'invalid structure'}
        result = self.run_fixture(json.dumps(malformed))
        self.assertNotEqual(result['status'], 'completed')
        self.assertEqual(result['finding_count'], 0)


class GenericRunnerOutputTests(unittest.TestCase):
    def setUp(self):
        self.module = load_file('isolated_generic_output', ROOT / 'vapt_tools/generic_runner.py')

    def run_fixture(self, code=0, timeout=False, tool='dig', json_content=None):
        process = SimpleNamespace(returncode=code, kill=lambda: None)
        calls = [0]
        def communicate(**kwargs):
            calls[0] += 1
            if timeout and calls[0] == 1:
                raise subprocess.TimeoutExpired('fixture', 1)
            return '', ''
        process.communicate = communicate
        def fake_popen(command, **kwargs):
            if json_content is not None and '-j' in command:
                Path(command[command.index('-j') + 1]).write_text(json_content, encoding='utf-8')
            return process
        with patch.object(self.module, 'resolve_executable', return_value='synthetic-not-executed'), \
             patch.object(self.module.subprocess, 'Popen', side_effect=fake_popen):
            return self.module.run_generic_tool(tool_id=tool, tool_name='Fixture',
                executable='synthetic-not-executed', target='synthetic.invalid',
                execution_type='scanner', timeout_seconds=1)

    def test_zero_exit_is_completed(self):
        self.assertEqual(self.run_fixture()['status'], 'completed')

    def test_nonzero_exit_is_not_clean_completion(self):
        self.assertNotEqual(self.run_fixture(code=2)['status'], 'completed')

    def test_timeout_is_not_clean_completion(self):
        self.assertNotEqual(self.run_fixture(code=-9, timeout=True)['status'], 'completed')

    def test_invalid_structured_output_is_not_clean_completion(self):
        result = self.run_fixture(tool='subdomain-discovery')
        self.assertTrue(result.get('json_output_error'))
        self.assertNotEqual(result['status'], 'completed')

    def test_valid_empty_structured_output_remains_successful(self):
        result = self.run_fixture(tool='subdomain-discovery', json_content='[]')
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['json_output'], [])

    def test_structured_parse_error_does_not_hide_timeout(self):
        result = self.run_fixture(code=-9, timeout=True, tool='subdomain-discovery')
        self.assertEqual(result['status'], 'timeout')


if __name__ == '__main__':
    unittest.main(verbosity=2)
